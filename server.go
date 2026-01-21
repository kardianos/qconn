package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

// ClientStatus represents the authorization state of a client certificate.
type ClientStatus uint8

const (
	// StatusUnknown indicates the client is not known to the store.
	StatusUnknown ClientStatus = iota
	// StatusUnauthenticated indicates the client has provisioned but not yet authorized.
	StatusUnauthenticated
	// StatusAuthenticated indicates the client is authorized to connect.
	StatusAuthenticated
	// StatusRevoked indicates the client's certificate has been revoked.
	StatusRevoked
)

func (s ClientStatus) String() string {
	switch s {
	case StatusUnknown:
		return "unknown"
	case StatusUnauthenticated:
		return "unauthenticated"
	case StatusAuthenticated:
		return "authenticated"
	case StatusRevoked:
		return "revoked"
	default:
		return "invalid"
	}
}

// ClientStore manages client authorization state by fingerprint.
// Entries are stored with certificate expiry for automatic cleanup.
type ClientStore interface {
	// GetClientStatus returns the authorization status of a client.
	// Returns StatusUnknown if the client is not found or has expired.
	GetClientStatus(fp FP) (ClientStatus, error)

	// SetClientStatus sets the authorization status of a client.
	// expiresAt is the certificate expiry time; entries are cleaned up after expiry.
	// authorizedMsgTypes specifies which message types the client is authorized to handle.
	// If status is StatusRevoked, all msgTypes are revoked and authorizedMsgTypes is ignored.
	// If status is StatusAuthenticated, authorizedMsgTypes stores the authorized types
	// (distinct from the client-advertised MsgTypes in ClientInfoUpdate).
	SetClientStatus(fp FP, status ClientStatus, expiresAt time.Time, authorizedMsgTypes []string) error

	// GetClientRecord returns the full client record for a fingerprint.
	// Returns nil if the client is not found.
	GetClientRecord(fp FP) (*ClientRecord, error)

	// UpdateClientInfo updates the client info fields (MachineIP, Devices, etc).
	// Only updates the specified fields; does not change status or expiry.
	UpdateClientInfo(fp FP, info *ClientInfoUpdate) error

	// SetClientRoles updates a client's assigned roles.
	SetClientRoles(fp FP, roles []string) error

	// ListClientRecord returns all non-expired client records matching the filter.
	// The filter can specify Status and Roles (persisted fields).
	// The Online field filter should be applied by the caller after merging with connection state.
	// If filter is nil, returns all non-expired records.
	ListClientRecord(filter *ClientRecordFilter) ([]*ClientRecord, error)

	// ValidAuthToken validates a self-authorization token.
	// Returns valid=true and an expiration time if the token authorizes the client.
	// Auth tokens are typically provisioned only on init and are special-purpose.
	// Once used, the authorization granted by the token is only valid for 24 hours.
	// Token-based authorization is ONLY valid for system (admin) messages.
	// The Allow method should restrict any other use (e.g., client-to-client routing).
	ValidAuthToken(token string, fp FP) (valid bool, expiresAt time.Time, err error)

	// Allow checks if an action is permitted between originator and target.
	// Called when a request is received or a response is sent.
	// originator is always the original requester, target is always the handler.
	// The Action parameter indicates direction (request or response).
	// A zero target FP indicates a system message.
	//
	// Implementation should check in sequence:
	//  1. If the target is system and the role is the Admin Role, check if there is a valid redeemed auth token. If so, allow.
	//  2. Ensure role is authorized for originator FP.
	//  3. Ensure target FP is allowed to provide msgType.
	//  4. Ensure role can send to msgType.
	//  5. If all checks pass, allow communication.
	//
	// Clients authorized via ValidAuthToken (self-authorize) should only be
	// allowed to send system messages. Deny client-to-client routing for
	// token-authorized clients.
	Allow(act Action, originator FP, target FP, msgType string, role string) (bool, error)
}

// ClientInfoUpdate contains fields that can be updated by the client.
// Clients can update this even when unauthenticated to advertise their capabilities.
type ClientInfoUpdate struct {
	MachineIP string       `cbor:"1,keyasint,omitempty"`
	RemoteIP  string       `cbor:"2,keyasint,omitempty"` // Set by server
	Devices   []DeviceInfo `cbor:"3,keyasint,omitempty"`
	MsgTypes  []string     `cbor:"4,keyasint,omitempty"` // Message types the client can handle
}

// AuthManager provides certificate operations.
type AuthManager interface {
	// ServerCertificate returns the server's TLS certificate for the given SNI.
	// For provisioning requests, sni will be the provisioning server name.
	// Return nil to use the default certificate.
	ServerCertificate(sni string) (*tls.Certificate, error)

	// VerifyClientCertificate verifies a client certificate.
	// rawCerts contains the certificate chain presented by the client.
	// For provisioning, verifies against the derived CA pool.
	// For normal clients, verifies against the main CA.
	VerifyClientCertificate(rawCerts [][]byte) error

	// RootCertPEM returns the root CA certificate in PEM format.
	RootCertPEM() ([]byte, error)

	// SignProvisioningCSR signs a CSR for a new client.
	SignProvisioningCSR(csrPEM []byte, hostname string) (certPEM []byte, err error)

	// SignRenewalCSR signs a CSR for certificate renewal.
	// The hostname is used as the CN in the new certificate.
	SignRenewalCSR(csrPEM []byte, hostname string) (certPEM []byte, err error)
}

// Default message size limits.
const (
	DefaultUnauthenticatedMaxMsgSize = 10 * 1024        // 10 KB
	DefaultAuthenticatedMaxMsgSize   = 10 * 1024 * 1024 // 10 MB
)

// ServerOpt configures a Server.
type ServerOpt struct {
	Auth    AuthManager
	Clients ClientStore

	RequestTimeout time.Duration

	// KeepalivePeriod sets the QUIC keepalive interval.
	KeepalivePeriod time.Duration

	// UnauthenticatedMaxMsgSize is the maximum message size for unauthenticated clients
	// (StateProvisioning and StatePendingAuth). Default is 10 KB.
	UnauthenticatedMaxMsgSize int64

	// AuthenticatedMaxMsgSize is the maximum message size for authenticated clients
	// (StateConnected). Default is 10 MB.
	AuthenticatedMaxMsgSize int64
}

// Server handles client connections and routes messages.
type Server struct {
	auth            AuthManager
	clients         ClientStore
	requestTimeout  time.Duration
	tlsCfg          *tls.Config
	keepAlivePeriod time.Duration

	// Message size limits.
	unauthenticatedMaxMsgSize int64
	authenticatedMaxMsgSize   int64

	mu       sync.RWMutex
	conns    map[FP]*clientConn
	machines map[string]FP          // machine name -> FP
	types    map[string]map[FP]bool // device type -> set of FPs

	routeMu sync.Mutex
	routes  map[routeKey]*pendingRoute
	nextID  atomic.Uint64

	system *systemTarget

	done chan struct{}
}

type routeKey struct {
	targetFP FP
	targetID MessageID
}

type pendingRoute struct {
	originFP     FP
	originID     MessageID
	originTarget Target
	targetFP     FP
	msgType      string
	role         string
	deadline     time.Time
}

// NewServer creates a new Server.
func NewServer(opt ServerOpt) (*Server, error) {
	if opt.Auth == nil {
		return nil, ErrNoCert
	}
	if opt.Clients == nil {
		return nil, ErrNoClientStore
	}

	timeout := opt.RequestTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Configure keepalive period.
	keepalive := opt.KeepalivePeriod
	if keepalive <= 0 {
		keepalive = defaultKeepalivePeriod
	}

	// Configure message size limits.
	unauthMaxMsg := opt.UnauthenticatedMaxMsgSize
	if unauthMaxMsg <= 0 {
		unauthMaxMsg = DefaultUnauthenticatedMaxMsgSize
	}
	authMaxMsg := opt.AuthenticatedMaxMsgSize
	if authMaxMsg <= 0 {
		authMaxMsg = DefaultAuthenticatedMaxMsgSize
	}

	s := &Server{
		auth:                      opt.Auth,
		clients:                   opt.Clients,
		keepAlivePeriod:           keepalive,
		requestTimeout:            timeout,
		unauthenticatedMaxMsgSize: unauthMaxMsg,
		authenticatedMaxMsgSize:   authMaxMsg,
		tlsCfg:                    BuildTLSConfig(opt.Auth),
		conns:                     make(map[FP]*clientConn),
		machines:                  make(map[string]FP),
		types:                     make(map[string]map[FP]bool),
		routes:                    make(map[routeKey]*pendingRoute),
	}

	s.system = &systemTarget{
		server:   s,
		handlers: s.buildSystemHandlers(),
	}

	return s, nil
}

func (s *Server) buildSystemHandlers() map[ConnState]map[string]serverHandler {
	return map[ConnState]map[string]serverHandler{
		StateProvisioning: {
			"provision-csr": s.handleProvision,
		},
		StatePendingAuth: {
			"self-authorize":     s.handleSelfAuthorize,
			"update-client-info": s.handleUpdateClientInfo, // Allow unauthenticated clients to advertise capabilities
		},
		StateConnected: {
			"renew":              s.handleRenew,
			"update-client-info": s.handleUpdateClientInfo,
			"register-devices":   s.handleRegisterDevices,
			"self-authorize":     s.handleSelfAuthorize, // Allow authenticated clients to get temp auth.

			AdminPrefix + "client/list":      s.handleListClients,
			AdminPrefix + "client/auth":      s.handleAuthorizeClient,
			AdminPrefix + "client/set-roles": s.handleSetClientRoles,
			AdminPrefix + "client/revoke":    s.handleRevokeClient,
		},
	}
}

// Serve starts accepting connections on the listener.
func (s *Server) Serve(ctx context.Context, conn net.PacketConn) error {
	s.done = make(chan struct{})

	quicConfig := &quic.Config{
		MaxIncomingStreams: 1000,
		KeepAlivePeriod:    s.keepAlivePeriod,
	}

	listener, err := quic.Listen(conn, s.tlsCfg, quicConfig)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		close(s.done)
		_ = listener.Close()
	}()

	// Start route timeout checker.
	go s.checkRouteTimeouts(ctx)

	for {
		quicConn, err := listener.Accept(ctx)
		if err != nil {
			return nil
		}
		go s.handleConnection(ctx, quicConn)
	}
}

func (s *Server) handleConnection(ctx context.Context, quicConn *quic.Conn) {
	state := quicConn.ConnectionState()
	certs := state.TLS.PeerCertificates
	if len(certs) == 0 {
		quicConn.CloseWithError(1, "no certificate")
		return
	}

	cert := certs[0]
	fp := FingerprintOf(cert)
	hostname := cert.Subject.CommonName

	conn := &clientConn{
		connFP:   fp,
		hostname: hostname,
		quicConn: quicConn,
	}

	// Determine initial state from certificate and auth status.
	if isProvisioningCert(cert) {
		conn.state = StateProvisioning
	} else {
		status, err := s.clients.GetClientStatus(fp)
		if err != nil {
			quicConn.CloseWithError(1, "client store error")
			return
		}
		switch status {
		case StatusRevoked:
			quicConn.CloseWithError(1, "certificate revoked")
			return
		case StatusAuthenticated:
			conn.state = StateConnected
		default:
			// StatusUnknown or StatusUnauthenticated
			conn.state = StatePendingAuth
		}
	}

	// Accept stream from client
	stream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		quicConn.CloseWithError(2, "stream error")
		return
	}
	conn.stream = stream
	conn.enc = cbor.NewEncoder(stream)

	// Set initial message size limit based on state.
	var initialLimit int64
	if conn.state == StateConnected {
		initialLimit = s.authenticatedMaxMsgSize
	} else {
		initialLimit = s.unauthenticatedMaxMsgSize
	}
	conn.limitedR = newLimitedReader(stream, initialLimit)
	conn.dec = cbor.NewDecoder(conn.limitedR)

	// Register connection - check for duplicate machine name
	s.mu.Lock()
	if existingFP, exists := s.machines[hostname]; exists && existingFP != fp {
		s.mu.Unlock()
		quicConn.CloseWithError(1, ErrDuplicateMachine.Error())
		return
	}
	s.conns[fp] = conn
	s.machines[hostname] = fp
	s.mu.Unlock()

	// Run read loop
	s.readLoop(ctx, conn)

	// Cleanup
	s.mu.Lock()
	delete(s.conns, fp)
	delete(s.machines, hostname)
	// Remove from type index
	for _, dev := range conn.devices {
		if typeSet := s.types[dev.Type]; typeSet != nil {
			delete(typeSet, fp)
			if len(typeSet) == 0 {
				delete(s.types, dev.Type)
			}
		}
	}
	s.mu.Unlock()
}

func (s *Server) readLoop(ctx context.Context, conn *clientConn) {
	for {
		// Reset the limit for each message.
		conn.limitedR.Reset()

		var msg Message
		if err := conn.dec.Decode(&msg); err != nil {
			return
		}

		if err := s.handleMessage(ctx, conn, &msg); err != nil {
			return
		}
	}
}

func (s *Server) handleMessage(ctx context.Context, conn *clientConn, msg *Message) error {
	switch msg.Action {
	case ActionRequest:
		return s.handleRequest(ctx, conn, msg)
	case ActionResponse:
		return s.handleResponse(ctx, conn, msg)
	case ActionAck:
		return s.handleAck(ctx, conn, msg)
	default:
		return s.sendError(ctx, conn, msg.ID, ErrInvalidAction.Error())
	}
}

func (s *Server) handleRequest(ctx context.Context, conn *clientConn, msg *Message) error {
	// Route to target (could be system or another client)
	if msg.Target.IsSystem() {
		return s.system.deliver(ctx, conn.connFP, msg)
	}

	return s.forwardRequest(ctx, conn, msg)
}

// resolveTarget finds the connection for a target.
// Returns the connection and the specific device name if targeting a device.
func (s *Server) resolveTarget(target Target) (*clientConn, string, error) {
	if err := target.Validate(); err != nil {
		return nil, "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// If targeting a specific machine (with or without device)
	if target.Machine != "" {
		fp, ok := s.machines[target.Machine]
		if !ok {
			return nil, "", ErrNotConnected
		}
		conn := s.conns[fp]
		if conn == nil {
			return nil, "", ErrNotConnected
		}

		// If targeting a specific device, verify it exists
		if target.Device != "" {
			found := false
			for _, dev := range conn.devices {
				if dev.Name == target.Device {
					found = true
					break
				}
			}
			if !found {
				return nil, "", ErrDeviceNotFound
			}
			return conn, target.Device, nil
		}

		return conn, "", nil
	}

	// Targeting by device type - find first matching connection
	if target.DeviceType != "" {
		typeSet := s.types[target.DeviceType]
		if len(typeSet) == 0 {
			return nil, "", ErrTypeNotFound
		}
		// Pick first available (could be randomized for load balancing)
		for fp := range typeSet {
			conn := s.conns[fp]
			if conn != nil {
				return conn, "", nil
			}
		}
		return nil, "", ErrTypeNotFound
	}

	return nil, "", ErrInvalidTarget
}

func (s *Server) forwardRequest(ctx context.Context, origin *clientConn, msg *Message) error {
	// Only connected clients can forward requests to other clients.
	if origin.state != StateConnected {
		return s.sendError(ctx, origin, msg.ID, ErrInvalidState.Error())
	}

	targetConn, _, err := s.resolveTarget(msg.Target)
	if err != nil {
		return s.sendError(ctx, origin, msg.ID, err.Error())
	}

	// Check if the request is allowed.
	allowed, err := s.clients.Allow(ActionRequest, origin.connFP, targetConn.connFP, msg.Type, msg.Role)
	if err != nil {
		return s.sendError(ctx, origin, msg.ID, err.Error())
	}
	if !allowed {
		return s.sendError(ctx, origin, msg.ID, "request not allowed")
	}

	targetID := MessageID(s.nextID.Add(1))

	now := time.Now()
	s.routeMu.Lock()
	s.routes[routeKey{targetConn.connFP, targetID}] = &pendingRoute{
		originFP:     origin.connFP,
		originID:     msg.ID,
		originTarget: origin.target(),
		targetFP:     targetConn.connFP,
		msgType:      msg.Type,
		role:         msg.Role,
		deadline:     now.Add(s.requestTimeout),
	}
	s.routeMu.Unlock()

	fwd := &Message{
		ID:      targetID,
		Action:  ActionRequest,
		Target:  msg.Target,
		From:    origin.target(),
		Type:    msg.Type,
		Payload: msg.Payload,
	}

	return targetConn.deliver(ctx, origin.target(), fwd)
}

func (s *Server) handleResponse(ctx context.Context, conn *clientConn, msg *Message) error {
	key := routeKey{conn.connFP, msg.ID}

	s.routeMu.Lock()
	route, ok := s.routes[key]
	if ok {
		delete(s.routes, key)
	}
	s.routeMu.Unlock()

	if !ok {
		return nil
	}

	s.mu.RLock()
	originConn := s.conns[route.originFP]
	s.mu.RUnlock()

	if originConn == nil {
		return nil // Origin disconnected
	}

	// Check if the response is allowed.
	// originator is the original requester, target is the responder.
	allowed, err := s.clients.Allow(ActionResponse, route.originFP, conn.connFP, route.msgType, route.role)
	if err != nil {
		return err
	}
	if !allowed {
		return nil // Silently drop disallowed response
	}

	resp := &Message{
		ID:      route.originID,
		Action:  ActionResponse,
		Target:  route.originTarget,
		Payload: msg.Payload,
		Error:   msg.Error,
	}

	return originConn.deliver(ctx, conn.target(), resp)
}

func (s *Server) handleAck(ctx context.Context, conn *clientConn, msg *Message) error {
	key := routeKey{conn.connFP, msg.ID}

	s.routeMu.Lock()
	route, ok := s.routes[key]
	if ok {
		// Extend the deadline.
		route.deadline = time.Now().Add(s.requestTimeout)
	}
	s.routeMu.Unlock()

	if !ok {
		return nil
	}

	s.mu.RLock()
	originConn := s.conns[route.originFP]
	s.mu.RUnlock()

	if originConn == nil {
		return nil
	}

	// Forward ack to origin.
	ack := &Message{
		ID:     route.originID,
		Action: ActionAck,
		Target: route.originTarget,
	}

	return originConn.deliver(ctx, conn.target(), ack)
}

// dispatchToConn sends a message to a specific connection.
func (s *Server) dispatchToConn(ctx context.Context, from Target, conn *clientConn, msg *Message) error {
	return conn.deliver(ctx, from, msg)
}

func (s *Server) sendError(ctx context.Context, to *clientConn, id MessageID, errMsg string) error {
	resp := &Message{
		ID:     id,
		Action: ActionResponse,
		Target: to.target(),
		Error:  errMsg,
	}
	return to.deliver(ctx, System(), resp)
}

func (s *Server) checkRouteTimeouts(ctx context.Context) {
	ticker := time.NewTicker(s.requestTimeout / 4)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.expireRoutes(ctx); err != nil {
				// Origin disconnected, ignore.
				continue
			}
		}
	}
}

func (s *Server) expireRoutes(ctx context.Context) error {
	now := time.Now()
	var expired []struct {
		key   routeKey
		route *pendingRoute
	}

	s.routeMu.Lock()
	for key, route := range s.routes {
		if now.After(route.deadline) {
			expired = append(expired, struct {
				key   routeKey
				route *pendingRoute
			}{key, route})
			delete(s.routes, key)
		}
	}
	s.routeMu.Unlock()

	// Send timeout errors to origins.
	var firstErr error
	for _, e := range expired {
		s.mu.RLock()
		originConn := s.conns[e.route.originFP]
		s.mu.RUnlock()

		if originConn != nil {
			if err := s.sendError(ctx, originConn, e.route.originID, ErrTimeout.Error()); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// System handlers

func (s *Server) handleProvision(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var req ProvisionRequest
	if err := cbor.Unmarshal(msg.Payload, &req); err != nil {
		return ErrInvalidRequest
	}

	// The client's certificate was already verified against the provisioning pool
	// in VerifyClientCertificate, which proves they have a valid provisioning token.

	certPEM, err := s.auth.SignProvisioningCSR(req.CSRPEM, req.Hostname)
	if err != nil {
		return err
	}

	rootPEM, err := s.auth.RootCertPEM()
	if err != nil {
		return err
	}

	resp := ProvisionResponse{
		CertPEM:   certPEM,
		RootCAPEM: rootPEM,
	}
	return cbor.NewEncoder(w).Encode(resp)
}

func (s *Server) handleRenew(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var req RenewRequest
	if err := cbor.Unmarshal(msg.Payload, &req); err != nil {
		return ErrInvalidRequest
	}

	// Check client is not revoked.
	status, err := s.clients.GetClientStatus(conn.connFP)
	if err != nil {
		return err
	}
	if status == StatusRevoked {
		return ErrClientRevoked
	}

	// Sign the renewal CSR with the client's hostname.
	certPEM, err := s.auth.SignRenewalCSR(req.CSRPEM, conn.hostname)
	if err != nil {
		return err
	}

	// Parse the new certificate to get its fingerprint and expiry.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ErrInvalidCertificate
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	newFP := FingerprintOf(newCert)

	// Get existing client record to preserve info.
	oldRec, err := s.clients.GetClientRecord(conn.connFP)
	if err != nil {
		return err
	}

	// Create new client record with the new FP, preserving authorized msg types.
	var authorizedMsgTypes []string
	if oldRec != nil {
		authorizedMsgTypes = oldRec.AuthorizedMsgTypes
	}
	if err := s.clients.SetClientStatus(newFP, status, newCert.NotAfter, authorizedMsgTypes); err != nil {
		return err
	}

	// Copy over client info and roles if we had an old record.
	if oldRec != nil {
		info := &ClientInfoUpdate{
			MachineIP: oldRec.MachineIP,
			RemoteIP:  oldRec.RemoteIP,
			Devices:   oldRec.Devices,
		}
		err = s.clients.UpdateClientInfo(newFP, info)
		if err != nil {
			return err
		}

		// Preserve roles.
		if len(oldRec.Roles) > 0 {
			err = s.clients.SetClientRoles(newFP, oldRec.Roles)
			if err != nil {
				return err
			}
		}
	}

	resp := RenewResponse{CertPEM: certPEM}
	return cbor.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListClients(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	// Get stored records (non-expired, no filter for now).
	records, err := s.clients.ListClientRecord(nil)
	if err != nil {
		return err
	}

	// Build map by FP for quick lookup.
	recordMap := make(map[FP]*ClientRecord, len(records))
	for _, rec := range records {
		recordMap[rec.Fingerprint] = rec
	}

	// Merge with active connections (outer join).
	s.mu.RLock()
	for fp, c := range s.conns {
		if rec, ok := recordMap[fp]; ok {
			// Enrich existing record with live data.
			rec.Online = true
			rec.Devices = c.devices // Use live device info.
		} else {
			// Add connection-only record (pending/provisioning).
			recordMap[fp] = &ClientRecord{
				Fingerprint: fp,
				Hostname:    c.hostname,
				Devices:     c.devices,
				Online:      true,
				// Status will be zero (StatusUnknown) for unrecorded connections.
			}
		}
	}
	s.mu.RUnlock()

	// Collect results.
	result := make([]*ClientRecord, 0, len(recordMap))
	for _, rec := range recordMap {
		result = append(result, rec)
	}

	return cbor.NewEncoder(w).Encode(result)
}

func (s *Server) handleRegisterDevices(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var req RegisterDevicesRequest
	if err := cbor.Unmarshal(msg.Payload, &req); err != nil {
		return ErrInvalidRequest
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove old device type mappings for this connection.
	for _, dev := range conn.devices {
		if typeSet := s.types[dev.Type]; typeSet != nil {
			delete(typeSet, conn.connFP)
			if len(typeSet) == 0 {
				delete(s.types, dev.Type)
			}
		}
	}

	// Store new devices.
	conn.devices = req.Devices

	// Add new device type mappings.
	for _, dev := range conn.devices {
		if s.types[dev.Type] == nil {
			s.types[dev.Type] = make(map[FP]bool)
		}
		s.types[dev.Type][conn.connFP] = true
	}

	return nil
}

func (s *Server) handleSelfAuthorize(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var req SelfAuthorizeRequest
	if err := cbor.Unmarshal(msg.Payload, &req); err != nil {
		return ErrInvalidRequest
	}

	valid, expiresAt, err := s.clients.ValidAuthToken(req.Token, conn.connFP)
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidAuthToken
	}

	// Update client store with token-based expiration.
	// Token-auth clients have nil authorized msg types (system messages only).
	if err := s.clients.SetClientStatus(conn.connFP, StatusAuthenticated, expiresAt, nil); err != nil {
		return err
	}

	// Update connection state and message size limit.
	s.mu.Lock()
	conn.state = StateConnected
	conn.limitedR.SetLimit(s.authenticatedMaxMsgSize)
	s.mu.Unlock()

	// Build response with state change notification including expiration.
	notification := StateChangeNotification{
		NewState:  StateConnected,
		ExpiresAt: expiresAt,
	}
	return cbor.NewEncoder(w).Encode(notification)
}

func (s *Server) handleAuthorizeClient(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var req AuthorizeClientRequest
	if err := cbor.Unmarshal(msg.Payload, &req); err != nil {
		return ErrInvalidRequest
	}
	if err := ack(ctx); err != nil {
		return err
	}

	// Get the client record to find the expiry.
	rec, err := s.clients.GetClientRecord(req.FP)
	if err != nil {
		return err
	}
	if rec == nil {
		return ErrNotConnected // Client never provisioned
	}
	expiresAt := rec.ExpiresAt

	// Update client store with authorized message types.
	if err := s.clients.SetClientStatus(req.FP, StatusAuthenticated, expiresAt, req.MsgTypes); err != nil {
		return err
	}

	// Set roles if provided.
	if len(req.Roles) > 0 {
		if err := s.clients.SetClientRoles(req.FP, req.Roles); err != nil {
			return err
		}
	}

	// If the target is connected, update its state and notify it.
	s.mu.Lock()
	targetConn := s.conns[req.FP]
	if targetConn != nil {
		targetConn.state = StateConnected
		targetConn.limitedR.SetLimit(s.authenticatedMaxMsgSize)
	}
	s.mu.Unlock()

	// Send state change notification if connected.
	if targetConn != nil {
		notification := StateChangeNotification{NewState: StateConnected}
		notifyPayload, err := cbor.Marshal(notification)
		if err != nil {
			return err
		}
		notifyMsg := &Message{
			ID:      MessageID(s.nextID.Add(1)),
			Action:  ActionRequest,
			Target:  targetConn.target(),
			Type:    "state-change",
			Payload: notifyPayload,
		}
		return targetConn.deliver(ctx, System(), notifyMsg)
	}

	return nil
}

func (s *Server) handleSetClientRoles(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var req SetClientRolesRequest
	if err := cbor.Unmarshal(msg.Payload, &req); err != nil {
		return ErrInvalidRequest
	}
	return s.clients.SetClientRoles(req.FP, req.Roles)
}

func (s *Server) handleRevokeClient(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var req RevokeClientRequest
	if err := cbor.Unmarshal(msg.Payload, &req); err != nil {
		return ErrInvalidRequest
	}

	// Get client record to preserve expiry time.
	rec, err := s.clients.GetClientRecord(req.FP)
	if err != nil {
		return err
	}

	var expiresAt time.Time
	if rec != nil {
		expiresAt = rec.ExpiresAt
	} else {
		// If no record, use a default expiry.
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	// Revoke the client.
	if err := s.clients.SetClientStatus(req.FP, StatusRevoked, expiresAt, nil); err != nil {
		return err
	}

	// If the client is currently connected, close their connection.
	s.mu.Lock()
	if targetConn := s.conns[req.FP]; targetConn != nil {
		targetConn.quicConn.CloseWithError(1, "certificate revoked")
	}
	s.mu.Unlock()

	return nil
}

func (s *Server) handleUpdateClientInfo(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error {
	var info ClientInfoUpdate
	if err := cbor.Unmarshal(msg.Payload, &info); err != nil {
		return ErrInvalidRequest
	}

	// Set RemoteIP from the server's perspective.
	if addr := conn.quicConn.RemoteAddr(); addr != nil {
		info.RemoteIP = addr.String()
	}

	// Update client store.
	if err := s.clients.UpdateClientInfo(conn.connFP, &info); err != nil {
		return err
	}

	// Also update the in-memory device mappings for routing.
	if info.Devices != nil {
		s.mu.Lock()
		// Remove old device type mappings.
		for _, dev := range conn.devices {
			if typeSet := s.types[dev.Type]; typeSet != nil {
				delete(typeSet, conn.connFP)
				if len(typeSet) == 0 {
					delete(s.types, dev.Type)
				}
			}
		}
		// Store new devices.
		conn.devices = info.Devices
		// Add new device type mappings.
		for _, dev := range conn.devices {
			if s.types[dev.Type] == nil {
				s.types[dev.Type] = make(map[FP]bool)
			}
			s.types[dev.Type][conn.connFP] = true
		}
		s.mu.Unlock()
	}

	return nil
}
