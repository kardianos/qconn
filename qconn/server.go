package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qstate"
	"github.com/quic-go/quic-go"
)

var serverConnTransitions = []qstate.Transition[qdef.ServerConnState]{
	// From New
	{From: qdef.ConnNew, To: qdef.ConnProvisioning, Name: "is_provisioning_cert"},
	{From: qdef.ConnNew, To: qdef.ConnPendingAuth, Name: "is_normal_cert"},
	{From: qdef.ConnNew, To: qdef.ConnDisconnected, Name: "immediate_disconnect"},

	// From Provisioning
	{From: qdef.ConnProvisioning, To: qdef.ConnDisconnected, Name: "provisioning_done"},

	// From PendingAuth
	{From: qdef.ConnPendingAuth, To: qdef.ConnAuthorized, Name: "auth_approved"},
	{From: qdef.ConnPendingAuth, To: qdef.ConnDisconnected, Name: "auth_denied_or_lost"},

	// From Authorized
	{From: qdef.ConnAuthorized, To: qdef.ConnDisconnected, Name: "connection_lost"},
}

// newServerConnMachine creates a state machine for server-side connection tracking.
func newServerConnMachine(on func(from, to qdef.ServerConnState, name string)) *qstate.Machine[qdef.ServerConnState] {
	return qstate.New(
		qdef.ConnNew,
		serverConnTransitions,
		on,
	)
}

// serverConnStateToClientState converts qdef.ServerConnState to qdef.ClientState for observer notifications.
func serverConnStateToClientState(s qdef.ServerConnState) qdef.ClientState {
	switch s {
	case qdef.ConnNew:
		return qdef.StateConnected // New connection is effectively "connected"
	case qdef.ConnProvisioning:
		return qdef.StateProvisioning
	case qdef.ConnPendingAuth:
		return qdef.StateConnected // Pending auth is still "connected" from observer perspective
	case qdef.ConnAuthorized:
		return qdef.StateAuthorized
	case qdef.ConnDisconnected:
		return qdef.StateDisconnected
	default:
		return qdef.StateDisconnected
	}
}

type machineInfo struct {
	LocalAddr netip.Addr
	Hostname  string
	Devices   []qdef.DeviceInfo
}

// provisioningCertEntry holds a provisioning certificate with its CA for regeneration.
type provisioningCertEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
	ca        tls.Certificate // CA for regenerating expired certs
}

// Server implements the QUIC server logic with integrated connection and role management.
type Server struct {
	addr                       string
	tlsConfig                  *tls.Config
	authManager                qdef.AuthorizationManager
	provisioningCerts          map[string]*provisioningCertEntry // SNI -> provisioning cert entry
	provisioningMu             sync.Mutex                        // Protects provisioningCerts
	mainCert                   tls.Certificate                   // Main server certificate
	observer                   qdef.ClientObserver
	keepAlivePeriod            time.Duration
	maxIncomingStreams         int64
	renewalLimiter             *rateLimiter[qdef.FP]
	provisioningLimiter        *rateLimiter[netip.Addr]
	maxMessageSize             int
	provisioningMaxMessageSize int
	Router                     qdef.StreamRouter
	cancel                     context.CancelFunc // Cancels background goroutines like rate limiter cleanup

	// Connection management.
	mu          sync.RWMutex
	activeConns map[qdef.FP]*quic.Conn     // fingerprint -> connection
	identities  map[qdef.FP]*qdef.Identity // fingerprint -> identity
	devices     map[qdef.FP]*machineInfo   // fingerprint -> devices (in-memory only, cleared on disconnect)
	defaultWait time.Duration

	// preAuthorized contains fingerprints to auto-authorize on connect.
	// This is only used for bootstrap scenarios; never add to it at runtime.
	preAuthorized map[qdef.FP]struct{}

	// Role definitions for permission checking.
	rolesMu  sync.RWMutex
	roleDefs map[string]qdef.RoleConfig

	// External integration
	observers     []qdef.ConnectionObserver
	messageRouter qdef.MessageRouter

	// Stream tracking for diagnostics.
	streamMu     sync.Mutex
	streamOpens  int64
	streamCloses int64
}

const (
	DefaultKeepAlivePeriod      = 45 * time.Second
	DefaultRenewalInterval      = 1 * time.Hour
	DefaultProvisioningInterval = 1 * time.Minute
)

var serverIdentity = qdef.Identity{
	Hostname: ":self-server:",
}

type ServerOpt struct {
	// ListenOn is the UDP address to listen on (e.g., ":4433").
	ListenOn string

	// ProvisionTokens is a list of shared secrets used to authorize new clients
	// during the provisioning phase. Multiple tokens allow for rotation without
	// disrupting in-progress provisioning.
	//
	// SECURITY: See qdef.GenerateDerivedCA for token management best practices
	// including rotation, revocation, and storage guidelines.
	ProvisionTokens []string

	// Auth is the AuthorizationManager responsible for verifying client identities,
	// managing revocation, and issuing/renewing client certificates.
	// It also provides the root CA certificate used for verifying client certificates.
	Auth qdef.AuthorizationManager

	// Observer receives lifecycle events and logs from the server.
	Observer qdef.ClientObserver

	// MessageRouter routes ServiceUser messages to external systems (e.g., gRPC).
	// The server tries local qconn clients first, then delegates to MessageRouter.
	MessageRouter qdef.MessageRouter

	// Observers receive connection lifecycle events.
	Observers []qdef.ConnectionObserver

	// DefaultWait is the default timeout for routing messages to clients.
	// If zero, defaults to 10 seconds.
	DefaultWait time.Duration

	// KeepAlivePeriod specifies how often to send QUIC keep-alive frames.
	KeepAlivePeriod time.Duration

	// RenewalInterval is the minimum time between certificate renewals for a client.
	// If zero, defaults to DefaultRenewalInterval.
	RenewalInterval time.Duration

	// ProvisioningInterval is the minimum time between provisioning attempts from the same IP.
	// If zero, defaults to DefaultProvisioningInterval.
	ProvisioningInterval time.Duration

	// MaxMessageSize is the maximum size for CBOR messages from authorized clients.
	// If zero, defaults to qdef.DefaultMaxMessageSize (1MB).
	MaxMessageSize int

	// ProvisioningMaxMessageSize is the maximum size for CBOR messages from provisioning clients.
	// If zero, defaults to qdef.ProvisioningMaxMessageSize (64KB).
	// This should be kept small since provisioning only needs CSR and hostname.
	ProvisioningMaxMessageSize int

	// MaxIncomingStreams is the maximum number of concurrent incoming bidirectional streams.
	// If zero, defaults to 1000. The quic-go library default of 100 is too low for
	// applications with frequent short-lived streams like device updates.
	MaxIncomingStreams int64
}

// NewServer creates a new QUIC server.
func NewServer(opt ServerOpt) (*Server, error) {
	if opt.Auth == nil {
		return nil, qdef.ErrAuthRequired
	}
	cert, err := opt.Auth.ServerCertificate()
	if err != nil {
		return nil, fmt.Errorf("qconn: failed to get server certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(opt.Auth.RootCert())

	provisioningPool := x509.NewCertPool()
	provisioningCerts := make(map[string]*provisioningCertEntry)
	for _, token := range opt.ProvisionTokens {
		ca, err := qdef.GenerateDerivedCA(token)
		if err == nil {
			leaf, err := x509.ParseCertificate(ca.Certificate[0])
			if err == nil {
				provisioningPool.AddCert(leaf)
			}
			// Generate a server cert signed by this derived CA.
			sni := qdef.ProvisioningServerName(token)
			serverCert, expiresAt, err := qdef.GenerateProvisioningServerCert(ca, sni)
			if err == nil {
				provisioningCerts[sni] = &provisioningCertEntry{
					cert:      &serverCert,
					expiresAt: expiresAt,
					ca:        ca,
				}
			}
		}
	}

	// Create a placeholder for the server so GetCertificate can reference it.
	var s *Server

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.getProvisioningCert(hello.ServerName)
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return qdef.ErrNoClientCert
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("qconn: failed to parse client cert: %w", err)
			}

			// Check if it's a provisioning certificate.
			var isProvisioning bool
			for _, ext := range leaf.Extensions {
				if ext.Id.Equal(qdef.OIDProvisioningIdentity) {
					isProvisioning = true
					break
				}
			}

			if isProvisioning {
				opts := x509.VerifyOptions{
					Roots:     provisioningPool,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}
				if _, err := leaf.Verify(opts); err != nil {
					return fmt.Errorf("qconn: invalid provisioning certificate: %w", err)
				}
				return nil
			}

			// Normal certificate validation.
			opts := x509.VerifyOptions{
				Roots:     caPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := leaf.Verify(opts); err != nil {
				return fmt.Errorf("qconn: failed to verify client certificate: %w", err)
			}

			fp := qdef.FingerprintOf(leaf)
			status, err := opt.Auth.GetStatus(fp)
			if err != nil {
				return fmt.Errorf("qconn: failed to get auth status for %s [%s]: %w", leaf.Subject.CommonName, fp, err)
			}
			if status == qdef.StatusRevoked {
				return qdef.ClientRevokedError{Hostname: leaf.Subject.CommonName, Fingerprint: fp}
			}
			return nil
		},
		Time: timeNow,
	}

	renewalInterval := opt.RenewalInterval
	if renewalInterval <= 0 {
		renewalInterval = DefaultRenewalInterval
	}

	provisioningInterval := opt.ProvisioningInterval
	if provisioningInterval <= 0 {
		provisioningInterval = DefaultProvisioningInterval
	}

	// Create a context for background goroutines (rate limiter cleanup).
	bgCtx, cancel := context.WithCancel(context.Background())

	maxMsgSize := opt.MaxMessageSize
	if maxMsgSize <= 0 {
		maxMsgSize = qdef.DefaultMaxMessageSize
	}
	provMaxMsgSize := opt.ProvisioningMaxMessageSize
	if provMaxMsgSize <= 0 {
		provMaxMsgSize = qdef.ProvisioningMaxMessageSize
	}

	defaultWait := opt.DefaultWait
	if defaultWait <= 0 {
		defaultWait = 10 * time.Second
	}

	s = &Server{
		addr:                       opt.ListenOn,
		tlsConfig:                  tlsConfig,
		authManager:                opt.Auth,
		provisioningCerts:          provisioningCerts,
		mainCert:                   cert,
		observer:                   opt.Observer,
		keepAlivePeriod:            opt.KeepAlivePeriod,
		maxIncomingStreams:         opt.MaxIncomingStreams,
		renewalLimiter:             newRateLimiter[qdef.FP](bgCtx, renewalInterval),
		provisioningLimiter:        newRateLimiter[netip.Addr](bgCtx, provisioningInterval),
		maxMessageSize:             maxMsgSize,
		provisioningMaxMessageSize: provMaxMsgSize,
		cancel:                     cancel,
		// Connection management
		activeConns:   make(map[qdef.FP]*quic.Conn),
		identities:    make(map[qdef.FP]*qdef.Identity),
		devices:       make(map[qdef.FP]*machineInfo),
		defaultWait:   defaultWait,
		preAuthorized: make(map[qdef.FP]struct{}),
		// Role definitions
		roleDefs: make(map[string]qdef.RoleConfig),
		// External integration
		observers:     opt.Observers,
		messageRouter: opt.MessageRouter,
	}

	// Register internal handlers.
	qdef.Handle(&s.Router, qdef.ServiceProvision, "", s.handleProvisioning)
	qdef.Handle(&s.Router, qdef.ServiceSystem, "renew", s.handleRenewal)
	qdef.Handle(&s.Router, qdef.ServiceSystem, "devices", s.handleDeviceUpdate)
	qdef.Handle(&s.Router, qdef.ServiceSystem, "list-clients", s.handleListClients)
	qdef.Handle(&s.Router, qdef.ServiceSystem, "authorize", s.handleAuthorize)
	qdef.Handle(&s.Router, qdef.ServiceSystem, "revoke", s.handleRevoke)

	return s, nil
}

// getProvisioningCert returns the provisioning certificate for the given SNI,
// regenerating it if it's close to expiry (within 1 hour).
// The provisioningCerts cache is setup on startup.
func (s *Server) getProvisioningCert(sni string) (*tls.Certificate, error) {
	s.provisioningMu.Lock()
	defer s.provisioningMu.Unlock()

	entry, ok := s.provisioningCerts[sni]
	if !ok {
		// Not a provisioning request, return nil to use default certificate.
		return nil, nil
	}

	// Check cached expiry - no X.509 parsing needed.
	if timeNow().Add(time.Hour).After(entry.expiresAt) {
		// Cert is expiring soon, regenerate it.
		newCert, expiresAt, err := qdef.GenerateProvisioningServerCert(entry.ca, sni)
		if err != nil {
			// Error regenerating, return existing cert.
			return entry.cert, nil
		}
		s.provisioningCerts[sni] = &provisioningCertEntry{
			cert:      &newCert,
			expiresAt: expiresAt,
			ca:        entry.ca,
		}
		return &newCert, nil
	}

	return entry.cert, nil
}

func (s *Server) logf(id qdef.Identity, format string, v ...any) {
	if s.observer == nil {
		return
	}
	s.observer.Logf(id, format, v...)
}

func (s *Server) notifyState(id qdef.Identity, state qdef.ClientState) {
	if s.observer != nil {
		s.observer.OnStateChange(id, state)
	}

	// Track identity for device routing.
	if state == qdef.StateConnected || state == qdef.StateAuthorized {
		s.mu.Lock()
		s.identities[id.Fingerprint] = &id
		s.mu.Unlock()
	}
}

func (s *Server) notifyConnect(id qdef.Identity) {
	for _, o := range s.observers {
		o.OnConnect(id)
	}
}

func (s *Server) notifyDisconnect(id qdef.Identity) {
	for _, o := range s.observers {
		o.OnDisconnect(id)
	}
}

func (s *Server) notifyDeviceUpdate(id qdef.Identity, devices []qdef.DeviceInfo) {
	for _, o := range s.observers {
		o.OnDeviceUpdate(id, devices)
	}
}

// Serve starts the server using pre-configured listeners. This is ideal for testing.
func (s *Server) Serve(ctx context.Context, packetConn net.PacketConn) error {
	kap := s.keepAlivePeriod
	if kap == 0 {
		kap = DefaultKeepAlivePeriod
	}
	maxStreams := s.maxIncomingStreams
	if maxStreams == 0 {
		maxStreams = 1000 // Default to 1000 instead of quic-go's 100
	}
	qc := &quic.Config{
		KeepAlivePeriod:    kap,
		MaxIdleTimeout:     kap * 4,
		MaxIncomingStreams: maxStreams,
	}
	listener, err := quic.Listen(packetConn, s.tlsConfig, qc)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener from PacketConn: %w", err)
	}

	go s.acceptLoop(ctx, listener)

	return nil
}

// ListenAndServe starts the QUIC server.
func (s *Server) ListenAndServe(ctx context.Context) error {
	packetConn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP packet conn: %w", err)
	}

	s.addr = packetConn.LocalAddr().String()
	s.logf(serverIdentity, "QUIC server listening on %s", s.addr)

	return s.Serve(ctx, packetConn)
}

// Close stops background goroutines like rate limiter cleanup.
// Call this when the server is shutting down.
func (s *Server) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

// StreamStats returns the number of stream opens, closes, and currently open streams.
func (s *Server) StreamStats() (opens, closes, open int64) {
	s.streamMu.Lock()
	opens = s.streamOpens
	closes = s.streamCloses
	s.streamMu.Unlock()
	open = opens - closes
	return
}

func (s *Server) trackStreamOpen() {
	s.streamMu.Lock()
	s.streamOpens++
	s.streamMu.Unlock()
}

func (s *Server) trackStreamClose() {
	s.streamMu.Lock()
	s.streamCloses++
	s.streamMu.Unlock()
}

// acceptLoop correctly takes the *quic.Listener struct pointer.
func (s *Server) acceptLoop(ctx context.Context, listener *quic.Listener) {
	defer func() { _ = listener.Close() }()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := listener.Accept(ctx)
		if err != nil {
			s.logf(serverIdentity, "failed to accept connection: %v", err)
			return
		}
		go func() {
			if err := s.handleConnection(ctx, conn); err != nil {
				// Only log unexpected errors, not normal disconnections.
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					s.logf(serverIdentity, "connection handler error: %v", err)
				}
			}
		}()
	}
}

func (s *Server) handleConnection(ctx context.Context, conn *quic.Conn) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logf(serverIdentity, "panic in handleConnection: %v", r)
			err = fmt.Errorf("internal server error: %v", r)
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cs := conn.ConnectionState()
	pcList := cs.TLS.PeerCertificates
	if len(pcList) == 0 {
		return qdef.ErrNoPeerCert
	}
	leaf := pcList[0]

	remoteAddrPort, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	id := qdef.Identity{
		Hostname:    leaf.Subject.CommonName,
		Address:     remoteAddrPort,
		Fingerprint: qdef.FingerprintOf(leaf),
		// Roles are managed server-side, not extracted from certificate.
	}

	// Create per-connection state machine.
	connState := newServerConnMachine(func(from, to qdef.ServerConnState, name string) {
		s.notifyState(id, serverConnStateToClientState(to))
	})

	// Check for provisioning extension.
	var isProvisioning bool
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(qdef.OIDProvisioningIdentity) {
			isProvisioning = true
			break
		}
	}

	// Track whether we stored the connection so we can clean up properly.
	var storedConnect bool
	defer func() {
		if err := connState.TransitionTo(qdef.ConnDisconnected); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}
		if storedConnect {
			s.mu.Lock()
			delete(s.activeConns, id.Fingerprint)
			delete(s.devices, id.Fingerprint) // Clear devices on disconnect (in-memory only)
			s.mu.Unlock()
			// Mark client as offline.
			s.authManager.UpdateClientAddr(id.Fingerprint, false, netip.AddrPort{}, "")
			s.notifyDisconnect(id)
		}
	}()

	switch isProvisioning {
	case true:
		// Transition: New -> Provisioning
		if err := connState.TransitionTo(qdef.ConnProvisioning); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}
	case false:
		// Transition: New -> PendingAuth
		if err := connState.TransitionTo(qdef.ConnPendingAuth); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}

		// Try auto-authorization for pre-authorized fingerprints.
		s.tryAutoAuthorize(id.Fingerprint)

		// Authorization check loop - wait until client is authorized.
		for {
			status, err := s.authManager.GetStatus(id.Fingerprint)
			if err == nil && status == qdef.StatusAuthorized {
				break // Authorized.
			}
			// Wait for status change or context cancellation.
			waitCtx, waitCancel := context.WithCancel(ctx)
			go func() {
				<-conn.Context().Done()
				waitCancel()
			}()
			s.authManager.WaitFor(waitCtx, id.Fingerprint)
			waitCancel()
			if ctx.Err() != nil || conn.Context().Err() != nil {
				return nil
			}
		}

		// Transition: PendingAuth -> Authorized
		if err := connState.TransitionTo(qdef.ConnAuthorized); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}

		// Store connection AFTER authorization is complete.
		// This prevents routing to unauthorized clients.
		s.mu.Lock()
		s.activeConns[id.Fingerprint] = conn
		s.mu.Unlock()
		storedConnect = true

		// Update client address, online status, and hostname.
		s.authManager.UpdateClientAddr(id.Fingerprint, true, id.Address, id.Hostname)

		// Notify observers.
		s.notifyConnect(id)
	}

	// Now that it's authorized (or provisioning), accept streams.
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-conn.Context().Done():
			return nil
		default:
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Log unless it's a clean shutdown (context cancelled or connection closed).
			if ctx.Err() == nil && conn.Context().Err() == nil {
				s.logf(id, "failed to accept stream: %v", err)
			}
			return nil
		}
		go s.handleStream(ctx, id, stream, isProvisioning)
	}
}

func (s *Server) handleStream(ctx context.Context, id qdef.Identity, stream *quic.Stream, provisioningCert bool) {
	s.trackStreamOpen()
	defer func() {
		_ = stream.Close()
		s.trackStreamClose()
	}()

	// Use strict size limits for provisioning clients to prevent abuse.
	maxSize := s.maxMessageSize
	if provisioningCert {
		maxSize = s.provisioningMaxMessageSize
	}
	dec := qdef.NewDecoder(stream, maxSize)
	enc := cbor.NewEncoder(stream)

	// Helper to send response message.
	sendMessage := func(respMsg *qdef.Message) {
		if encErr := enc.Encode(respMsg); encErr != nil {
			s.logf(id, "failed to encode response: %v", encErr)
		}
	}

	// Loop to handle multiple messages per stream (multiplexed streams).
	for {
		var msg qdef.Message
		if err := dec.Decode(&msg); err != nil {
			if err != io.EOF {
				s.logf(id, "failed to decode message: %v", err)
			}
			return
		}

		if provisioningCert {
			msg.Target.Service = qdef.ServiceProvision
		} else {
			if msg.Target.Service == qdef.ServiceProvision {
				msg.Target.Service = qdef.ServiceUser
			}
		}

		// Helper to send typed response (marshals to CBOR).
		sendResponse := func(resp any, respErr error) {
			var respMsg qdef.Message
			respMsg.ID = msg.ID
			if respErr != nil {
				respMsg.Error = respErr.Error()
			} else {
				payload, err := cbor.Marshal(resp)
				if err != nil {
					s.logf(id, "failed to marshal response for %s/%s: %v", msg.Target.Service, msg.Target.Type, err)
					respMsg.Error = fmt.Sprintf("failed to marshal response: %v", err)
				} else {
					respMsg.Payload = payload
				}
			}
			sendMessage(&respMsg)
		}

		// Try registered handlers first (ServiceProvision, ServiceSystem).
		resp, err := s.Router.Dispatch(ctx, id, msg)
		if err == nil {
			sendResponse(resp, nil)
			continue
		}

		// If no handler found, route the message to target machine.
		if errors.Is(err, qdef.ErrNoHandler) {
			// Look up the sender's full identity with roles from our stored state.
			senderID := s.getIdentity(id.Fingerprint)
			if senderID.Hostname == "" {
				senderID.Hostname = id.Hostname
			}
			if !senderID.Address.IsValid() {
				senderID.Address = id.Address
			}

			respMsg, routeErr := s.route(ctx, senderID, msg)
			if routeErr != nil {
				sendResponse(nil, routeErr)
				continue
			}
			sendMessage(respMsg)
			continue
		}

		// Log dispatch errors and send error response.
		s.logf(id, "dispatch error for %s/%s: %v", msg.Target.Service, msg.Target.Type, err)
		sendResponse(nil, err)
	}
}

func (s *Server) handleRenewal(ctx context.Context, id qdef.Identity, req *qdef.RenewalRequest) (*qdef.CredentialResponse, error) {
	// Rate limit: atomically check and record to prevent race conditions.
	if allowed, remaining := s.renewalLimiter.allow(id.Fingerprint); !allowed {
		return nil, qdef.RateLimitError{Operation: "renewal", Target: id.Fingerprint.String(), Wait: remaining}
	}

	certPEM, err := s.authManager.SignRenewalCSR(req.CSRPEM, id.Fingerprint)
	if err != nil {
		return nil, err
	}

	return &qdef.CredentialResponse{CertPEM: certPEM}, nil
}

func (s *Server) handleProvisioning(ctx context.Context, id qdef.Identity, req *qdef.ProvisioningRequest) (*qdef.CredentialResponse, error) {
	// Rate limit by IP address (provisioning clients don't have fingerprints yet).
	var clientIP netip.Addr
	if id.Address.IsValid() {
		clientIP = id.Address.Addr()
	}
	// Reject requests with empty/invalid addresses to prevent rate limit bypass.
	if !clientIP.IsValid() {
		return nil, qdef.ErrInvalidAddress
	}

	// Atomically check and record to prevent race conditions.
	if allowed, remaining := s.provisioningLimiter.allow(clientIP); !allowed {
		return nil, qdef.RateLimitError{Operation: "provisioning", Target: clientIP.String(), Wait: remaining}
	}

	provId := qdef.Identity{Hostname: req.Hostname, Address: id.Address}
	s.notifyState(provId, qdef.StateProvisioning)

	certPEM, err := s.authManager.SignProvisioningCSR(req.CSRPEM, req.Hostname, req.Roles)
	if err != nil {
		return nil, err
	}

	s.notifyState(provId, qdef.StateProvisioned)

	// Include root CA so client can verify server on future connections.
	rootCAPEM := qdef.EncodeCertPEM(s.authManager.RootCert())

	return &qdef.CredentialResponse{CertPEM: certPEM, RootCAPEM: rootCAPEM}, nil
}

// SetRoleDef configures a role's capabilities.
func (s *Server) SetRoleDef(name string, config qdef.RoleConfig) {
	s.rolesMu.Lock()
	defer s.rolesMu.Unlock()
	s.roleDefs[name] = config
}

// allowRole checks if a client is allowed to send to a job type.
// Returns true if the client's authorized roles allow sending to dest.
func (s *Server) allowRole(fp qdef.FP, dest string) (bool, error) {
	if len(dest) == 0 {
		return false, nil
	}

	// Get client info from auth manager.
	clients := s.authManager.ListClientsInfo(true, []qdef.FP{fp})
	if len(clients) == 0 {
		return false, qdef.ErrUnknownClient
	}
	client := clients[0]

	// Only authorized clients can participate.
	if !client.Authorized {
		return false, nil
	}

	// Check if client's roles allow sending to dest.
	s.rolesMu.RLock()
	defer s.rolesMu.RUnlock()

	for _, roleName := range client.RequestedRoles {
		def, ok := s.roleDefs[roleName]
		if !ok {
			continue
		}
		for _, sendsTo := range def.SendsTo {
			if sendsTo == dest {
				return true, nil
			}
		}
	}

	return false, nil
}

// allowRoleDirect checks if a named role allows a communication pattern.
// This is used for bridge scenarios where the sender doesn't have a registered fingerprint.
func (s *Server) allowRoleDirect(roleName, dest string) bool {
	s.rolesMu.RLock()
	defer s.rolesMu.RUnlock()

	def, ok := s.roleDefs[roleName]
	if !ok {
		return false
	}

	for _, sendsTo := range def.SendsTo {
		if sendsTo == dest {
			return true
		}
	}

	return false
}

// SetPreAuthorized marks a fingerprint for automatic authorization when it connects.
// When a client with this fingerprint connects, their status will be automatically
// set to StatusAuthorized (if it's not already) using their requested roles.
func (s *Server) SetPreAuthorized(fingerprint qdef.FP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preAuthorized[fingerprint] = struct{}{}
}

// isPreAuthorized checks if a fingerprint is marked for automatic authorization.
func (s *Server) isPreAuthorized(fingerprint qdef.FP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.preAuthorized[fingerprint]
	return ok
}

// tryAutoAuthorize attempts to auto-authorize a pre-authorized fingerprint.
// Returns true if auto-authorization was successful.
func (s *Server) tryAutoAuthorize(fp qdef.FP) bool {
	if !s.isPreAuthorized(fp) {
		return false
	}

	// Check if already authorized.
	status, err := s.authManager.GetStatus(fp)
	if err == nil && status == qdef.StatusAuthorized {
		return true // Already authorized.
	}

	// Set the client status to authorized.
	if err := s.authManager.SetClientStatus(fp, qdef.StatusAuthorized); err != nil {
		return false
	}

	return true
}

// SetMessageRouter sets the message router for external routing.
// This can be called after server creation to resolve chicken-and-egg dependencies.
func (s *Server) SetMessageRouter(r qdef.MessageRouter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messageRouter = r
}

// AddConnectionObserver adds an observer for connection lifecycle events.
func (s *Server) AddConnectionObserver(o qdef.ConnectionObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observers = append(s.observers, o)
}

func (s *Server) getIdentity(fingerprint qdef.FP) qdef.Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if val, ok := s.identities[fingerprint]; ok {
		return *val
	}
	return qdef.Identity{Fingerprint: fingerprint}
}

// hasDevice checks if a client has declared a specific device ID.
func (s *Server) hasDevice(fingerprint qdef.FP, deviceID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.devices[fingerprint]
	if !ok {
		return false
	}
	for _, d := range m.Devices {
		if d.ID == deviceID {
			return true
		}
	}
	return false
}

// route routes a message from a sender to a target client.
func (s *Server) route(ctx context.Context, senderID qdef.Identity, msg qdef.Message) (*qdef.Message, error) {
	deadline := time.Now().Add(s.defaultWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	// Try fingerprint-based auth first, fallback to role-based for bridge.
	allowed, err := s.allowRole(senderID.Fingerprint, msg.Target.Type)
	if err != nil || !allowed {
		// Fallback: check roles directly (for bridge scenarios).
		allowed = false
		for _, role := range senderID.Roles {
			if s.allowRoleDirect(role, msg.Target.Type) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return nil, qdef.UnauthorizedRoleError{Roles: senderID.Roles, JobType: msg.Target.Type}
	}

	for {
		// First try local qconn clients.
		conn, err := s.findTarget(msg.Target.Machine)
		if err == nil {
			// Check if sender has permission to send this job type.
			if senderID.Fingerprint.IsZero() && len(senderID.Roles) == 0 {
				return nil, fmt.Errorf("%w: sender fingerprint or roles required", qdef.ErrUnauthorized)
			}

			// Validate device ID if specified.
			receiverFP := msg.Target.Machine
			if msg.Target.Device != "" && !s.hasDevice(receiverFP, msg.Target.Device) {
				return nil, qdef.DeviceNotFoundError{Machine: receiverFP, DeviceID: msg.Target.Device}
			}

			return s.forward(ctx, conn, msg)
		}

		// Try MessageRouter for external targets (e.g., gRPC machines).
		if s.messageRouter != nil {
			resp, err := s.messageRouter.RouteMessage(ctx, senderID, msg)
			if err == nil {
				return resp, nil
			}
			// If MessageRouter doesn't handle it, continue waiting for local client.
			if !errors.Is(err, qdef.ErrNotHandled) {
				return nil, err
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
			if time.Now().After(deadline) {
				return nil, qdef.TargetUnavailableError{Target: msg.Target}
			}
		}
	}
}

func (s *Server) findTarget(fingerprint qdef.FP) (*quic.Conn, error) {
	s.mu.RLock()
	val, ok := s.activeConns[fingerprint]
	s.mu.RUnlock()
	if !ok {
		id := s.getIdentity(fingerprint)
		return nil, qdef.MachineNotConnectedError{Identity: id}
	}
	return val, nil
}

func (s *Server) forward(ctx context.Context, conn *quic.Conn, msg qdef.Message) (*qdef.Message, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	if err := cbor.NewEncoder(stream).Encode(msg); err != nil {
		return nil, err
	}

	var resp qdef.Message
	if err := cbor.NewDecoder(stream).Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Request is a high-level helper that handles ID generation and CBOR abstraction.
func (s *Server) Request(ctx context.Context, senderID qdef.Identity, target qdef.Addr, payload any, response any) error {
	rawPayload, err := cbor.Marshal(payload)
	if err != nil {
		return err
	}

	msg := qdef.Message{
		ID:      qdef.MessageID(time.Now().UnixNano()),
		Target:  target,
		Payload: rawPayload,
	}

	respMsg, err := s.route(ctx, senderID, msg)
	if err != nil {
		return err
	}

	if respMsg.Error != "" {
		return fmt.Errorf("%s", respMsg.Error)
	}

	if response != nil {
		return cbor.Unmarshal(respMsg.Payload, response)
	}
	return nil
}

// RequestUser sends a request to a user-level service on a target machine.
// This is the safe method for bridges to use - it enforces ServiceUser routing.
func (s *Server) RequestUser(ctx context.Context, senderID qdef.Identity, machine qdef.FP, serviceType, device string, payload any, response any) error {
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Machine: machine,
		Type:    serviceType,
		Device:  device,
	}
	return s.Request(ctx, senderID, target, payload, response)
}

func (s *Server) handleDeviceUpdate(ctx context.Context, id qdef.Identity, req *qdef.DeviceUpdateRequest) (*struct{}, error) {
	s.mu.Lock()
	// Store devices in server map (in-memory only).
	m, ok := s.devices[id.Fingerprint]
	if !ok {
		m = &machineInfo{}
		s.devices[id.Fingerprint] = m
	}
	m.LocalAddr = req.LocalAddr
	m.Hostname = req.Hostname
	m.Devices = req.Devices

	// Ensure identity is tracked for routing.
	existingID, ok := s.identities[id.Fingerprint]
	if !ok {
		existingID = &qdef.Identity{Fingerprint: id.Fingerprint}
		s.identities[id.Fingerprint] = existingID
	}
	if existingID.Hostname == "" {
		existingID.Hostname = id.Hostname
	}
	if !existingID.Address.IsValid() {
		existingID.Address = id.Address
	}
	s.mu.Unlock()

	// Notify observers of the device update with rich device info.
	s.notifyDeviceUpdate(*existingID, req.Devices)

	return &struct{}{}, nil
}

func (s *Server) handleListClients(ctx context.Context, id qdef.Identity, req *qdef.ListClientsReq) (*qdef.ListClientsResp, error) {
	allow, err := s.allowRole(id.Fingerprint, "list-clients")
	if err != nil {
		return nil, err
	}
	if !allow {
		return nil, qdef.UnauthorizedTargetError{Target: id.Fingerprint, JobType: "list-clients"}
	}

	clients := s.authManager.ListClientsInfo(req.ShowUnauthorized, req.Fingerprint)

	// Set Online status from activeConns and Self from requester's fingerprint.
	s.mu.RLock()
	for i := range clients {
		c := &clients[i]
		_, c.Online = s.activeConns[c.Fingerprint]
		c.Self = c.Fingerprint == id.Fingerprint

		// Include devices from server's in-memory map if requested.
		if req.IncludeDevices {
			if m, ok := s.devices[c.Fingerprint]; ok {
				c.Hostname = m.Hostname
				c.LocalAddr = m.LocalAddr
				c.Devices = m.Devices
			}
		}
	}
	s.mu.RUnlock()

	// Include external targets from MessageRouter if requested.
	if req.IncludeExternal {
		s.mu.RLock()
		mr := s.messageRouter
		s.mu.RUnlock()
		if mr != nil {
			external := s.messageRouter.ListTargets(req.Fingerprint)
			clients = append(clients, external...)
		}
	}

	return &qdef.ListClientsResp{Clients: clients}, nil
}

func (s *Server) handleAuthorize(ctx context.Context, id qdef.Identity, req *qdef.AuthorizeReq) (*struct{}, error) {
	allow, err := s.allowRole(id.Fingerprint, "authorize")
	if err != nil {
		return nil, err
	}
	if !allow {
		return nil, qdef.UnauthorizedTargetError{Target: id.Fingerprint, JobType: "authorize"}
	}

	// Set the client status to authorized.
	if err := s.authManager.SetClientStatus(req.Fingerprint, qdef.StatusAuthorized); err != nil {
		return nil, fmt.Errorf("set client status: %w", err)
	}

	return &struct{}{}, nil
}

func (s *Server) handleRevoke(ctx context.Context, id qdef.Identity, req *qdef.RevokeReq) (*struct{}, error) {
	allow, err := s.allowRole(id.Fingerprint, "revoke")
	if err != nil {
		return nil, err
	}
	if !allow {
		return nil, qdef.UnauthorizedTargetError{Target: id.Fingerprint, JobType: "revoke"}
	}

	// Set the client status to revoked.
	if err := s.authManager.SetClientStatus(req.Fingerprint, qdef.StatusRevoked); err != nil {
		return nil, fmt.Errorf("set client status: %w", err)
	}

	return &struct{}{}, nil
}
