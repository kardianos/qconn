package qconn

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qstore"
	"github.com/quic-go/quic-go"
)

// defaultKeepalivePeriod for quic protocol.
const defaultKeepalivePeriod = 45 * time.Second

// Resolver resolves hostnames to addresses for connecting.
type Resolver interface {
	// Resolve returns the address (host:port) to connect to.
	// The hostname is the logical server name (may differ from the resolved address).
	Resolve(ctx context.Context, hostname string) (addr string, err error)
}

// DNSResolver resolves hostnames using a specific DNS server.
type DNSResolver struct {
	// Nameserver is the DNS server address (e.g., "8.8.8.8:53").
	Nameserver string
	// Port is the port to append to resolved addresses.
	Port string
}

// Resolve queries the configured nameserver for the hostname.
func (r *DNSResolver) Resolve(ctx context.Context, hostname string) (string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", r.Nameserver)
		},
	}

	addrs, err := resolver.LookupHost(ctx, hostname)
	if err != nil {
		return "", fmt.Errorf("dns lookup failed: %w", err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for %s", hostname)
	}

	return net.JoinHostPort(addrs[0], r.Port), nil
}

// SystemHandler handles system messages from the server.
// Unlike regular handlers, system handlers don't send responses.
type SystemHandler func(ctx context.Context, msg *Message)

// Client connects to a qconn server.
type Client struct {
	quicConn *quic.Conn
	stream   *quic.Stream
	enc      *cbor.Encoder
	dec      *cbor.Decoder

	sendMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[MessageID]chan *Message
	nextID    atomic.Uint64

	handler            Handler
	systemHandlers     map[string]SystemHandler
	defaultRequestRole string

	// store is used to persist configuration like provision tokens.
	store qstore.DataStore
	// auth is used for certificate renewal.
	auth CredentialStore

	stateMu   sync.RWMutex
	state     ConnState
	stateCond *sync.Cond

	done chan struct{}
}

// ClientOpt configures a Client.
type ClientOpt struct {
	// ServerAddr is the server address to connect to.
	// If Resolver is set, this is treated as a hostname to resolve.
	// If empty and Store is set, retrieved from Store with key "server".
	// Stored to Store on first use if provided.
	ServerAddr string

	// Auth manages client credentials.
	Auth CredentialStore

	// Store is an optional data store for persisting client configuration.
	// Used to store/retrieve server address.
	Store qstore.DataStore

	// Handler processes incoming requests from other clients.
	Handler Handler

	// Resolver optionally resolves ServerAddr before connecting.
	// If nil, ServerAddr is used directly.
	Resolver Resolver

	// KeepalivePeriod sets the QUIC keepalive interval.
	KeepalivePeriod time.Duration

	// DefaultRoles are the roles this client requests from the server.
	// These are advertised to the server but must be explicitly authorized.
	DefaultRoles []string

	// DefaultRequestRole is the role used for Request() calls when role is empty.
	DefaultRequestRole string
}

// NewClient creates and connects a new client.
// If Auth.NeedsProvisioning() returns true, provisions first then reconnects.
func NewClient(ctx context.Context, opt ClientOpt) (*Client, error) {
	if opt.Auth == nil {
		return nil, ErrNoCert
	}

	// Resolve server address: use provided, or retrieve from store.
	serverAddr := opt.ServerAddr
	if serverAddr == "" && opt.Store != nil {
		if data, err := opt.Store.Get("server", false); err == nil && len(data) > 0 {
			serverAddr = string(data)
		}
	}
	if serverAddr == "" {
		return nil, fmt.Errorf("no server address configured")
	}

	// Store server address for future use if store is available.
	if opt.Store != nil && opt.ServerAddr != "" {
		_ = opt.Store.Set("server", false, []byte(opt.ServerAddr))
	}

	// Resolve server address if resolver is configured.
	resolvedAddr := serverAddr
	if opt.Resolver != nil {
		resolved, err := opt.Resolver.Resolve(ctx, serverAddr)
		if err != nil {
			return nil, err
		}
		resolvedAddr = resolved
	}

	tlsCfg, err := opt.Auth.TLSConfig()
	if err != nil {
		return nil, err
	}

	// Configure keepalive period.
	keepalive := opt.KeepalivePeriod
	if keepalive <= 0 {
		keepalive = defaultKeepalivePeriod
	}

	quicConfig := &quic.Config{
		MaxIncomingStreams: 1000,
		KeepAlivePeriod:    keepalive,
	}

	quicConn, err := quic.DialAddr(ctx, resolvedAddr, tlsCfg, quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		quicConn.CloseWithError(1, "stream error")
		return nil, err
	}

	// If we need to provision, do it on this connection then reconnect.
	if opt.Auth.NeedsProvisioning() {
		err := doProvisioning(ctx, stream, opt.Auth)
		quicConn.CloseWithError(0, "provisioning complete")
		if err != nil {
			return nil, err
		}

		// Re-resolve in case address changed.
		if opt.Resolver != nil {
			resolved, err := opt.Resolver.Resolve(ctx, serverAddr)
			if err != nil {
				return nil, err
			}
			resolvedAddr = resolved
		}

		// Reconnect with new credentials.
		tlsCfg, err = opt.Auth.TLSConfig()
		if err != nil {
			return nil, err
		}

		quicConn, err = quic.DialAddr(ctx, resolvedAddr, tlsCfg, quicConfig)
		if err != nil {
			return nil, err
		}

		stream, err = quicConn.OpenStreamSync(ctx)
		if err != nil {
			quicConn.CloseWithError(1, "stream error")
			return nil, err
		}
	}

	// Channel to signal when server has sent initial state notification.
	ready := make(chan struct{})

	enc := cbor.NewEncoder(stream)

	// Send initial "connect" message to trigger server's AcceptStream.
	// In QUIC, the server's AcceptStream only returns when the client sends data.
	connectMsg := &Message{
		ID:     1,
		Action: ActionRequest,
		Target: System(),
		Type:   "connect",
	}
	if err := enc.Encode(connectMsg); err != nil {
		quicConn.CloseWithError(1, "connect error")
		return nil, err
	}

	c := &Client{
		quicConn:           quicConn,
		stream:             stream,
		enc:                enc,
		dec:                cbor.NewDecoder(stream),
		pending:            make(map[MessageID]chan *Message),
		handler:            opt.Handler,
		systemHandlers:     make(map[string]SystemHandler),
		defaultRequestRole: opt.DefaultRequestRole,
		store:              opt.Store,
		auth:               opt.Auth,
		state:              StatePendingAuth, // Initial state after connection
		done:               make(chan struct{}),
	}
	c.stateCond = sync.NewCond(&c.stateMu)

	// Register state-change handler that also signals readiness.
	var readyOnce sync.Once
	c.systemHandlers["state-change"] = func(ctx context.Context, msg *Message) {
		c.handleStateChange(ctx, msg)
		readyOnce.Do(func() { close(ready) })
	}

	// Register handler for provision token rotation.
	c.systemHandlers["rotate-provision-token"] = c.handleRotateProvisionToken

	// Register handler for certificate renewal trigger.
	c.systemHandlers["trigger-renewal"] = c.handleTriggerRenewal

	go c.readLoop(ctx)

	// Wait for server to signal it has finished connection setup.
	// This ensures the server has added us to s.conns before we return.
	select {
	case <-ready:
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}

	return c, nil
}

// State returns the current connection state.
func (c *Client) State() ConnState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

// IsConnected returns true if the client is in the connected (authorized) state.
func (c *Client) IsConnected() bool {
	return c.State() == StateConnected
}

// WaitForConnected blocks until the client reaches the connected state or the context is cancelled.
// Returns nil if connected, or the context error if cancelled.
func (c *Client) WaitForConnected(ctx context.Context) error {
	// Use a polling approach with the condition variable
	c.stateMu.Lock()
	for c.state != StateConnected {
		c.stateMu.Unlock()

		// Check context
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Wait for state change with a short timeout
		waitDone := make(chan struct{})
		go func() {
			c.stateMu.Lock()
			c.stateCond.Wait()
			c.stateMu.Unlock()
			close(waitDone)
		}()

		select {
		case <-waitDone:
			// Continue to check state
		case <-ctx.Done():
			c.stateCond.Broadcast() // Wake up waiting goroutine
			<-waitDone              // Wait for it to finish
			return ctx.Err()
		}

		c.stateMu.Lock()
	}
	c.stateMu.Unlock()
	return nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	close(c.done)
	return c.quicConn.CloseWithError(0, "client closing")
}

// Request sends a request to a target and waits for response.
// The role parameter is used for RBAC authorization checks on the server.
// If role is empty, the client's DefaultRequestRole is used.
// For system messages, role can be empty. For client-to-client messages with RBAC enabled,
// role is required.
func (c *Client) Request(ctx context.Context, target Target, role string, req Request, resp any) error {
	if role == "" {
		role = c.defaultRequestRole
	}
	id := MessageID(c.nextID.Add(1))

	payload, err := cbor.Marshal(req)
	if err != nil {
		return err
	}

	msg := &Message{
		ID:      id,
		Action:  ActionRequest,
		Target:  target,
		Type:    req.Type(),
		Role:    role,
		Payload: payload,
	}

	respChan := make(chan *Message, 1)

	c.pendingMu.Lock()
	c.pending[id] = respChan
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
	}()

	c.sendMu.Lock()
	err = c.enc.Encode(msg)
	c.sendMu.Unlock()
	if err != nil {
		return err
	}

	for {
		select {
		case r := <-respChan:
			if r.Action == ActionAck {
				continue
			}
			if r.Error != "" {
				return &RequestError{Message: r.Error}
			}
			if resp != nil && len(r.Payload) > 0 {
				return cbor.Unmarshal(r.Payload, resp)
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return ErrNotConnected
		}
	}
}

// RequestError is returned when the server returns an error response.
type RequestError struct {
	Message string
}

func (e *RequestError) Error() string {
	return e.Message
}

func (c *Client) readLoop(ctx context.Context) {
	for {
		var msg Message
		if err := c.dec.Decode(&msg); err != nil {
			return
		}

		switch msg.Action {
		case ActionResponse, ActionAck:
			c.handleResponse(&msg)
		case ActionRequest:
			// Check for system messages.
			if msg.Target.IsSystem() {
				if handler, ok := c.systemHandlers[msg.Type]; ok {
					handler(ctx, &msg)
				}
				continue
			}
			if err := c.handleRequest(ctx, &msg); err != nil {
				return
			}
		}
	}
}

func (c *Client) handleStateChange(_ context.Context, msg *Message) {
	var notification StateChangeNotification
	if err := cbor.Unmarshal(msg.Payload, &notification); err != nil {
		return
	}

	c.stateMu.Lock()
	c.state = notification.NewState
	c.stateCond.Broadcast()
	c.stateMu.Unlock()
}

func (c *Client) handleRotateProvisionToken(_ context.Context, msg *Message) {
	if c.auth == nil {
		return // No auth configured, can't save token
	}

	var notification RotateTokenNotification
	if err := cbor.Unmarshal(msg.Payload, &notification); err != nil {
		return
	}

	// Store the new provision token in the credential store.
	_ = c.auth.SetProvisionToken(notification.Token)
}

func (c *Client) handleTriggerRenewal(ctx context.Context, msg *Message) {
	if c.auth == nil {
		return // No auth manager, can't renew
	}

	// Generate new CSR with current hostname.
	csrPEM, keyPEM, err := CreateCSR(c.auth.Hostname())
	if err != nil {
		return
	}

	// Send renewal request to server.
	req := RenewRequest{CSRPEM: csrPEM}
	var resp RenewResponse
	if err := c.Request(ctx, System(), "", &req, &resp); err != nil {
		return
	}

	// Save new credentials. Pass nil for root CA since it doesn't change during renewal.
	_ = c.auth.SaveCredentials(resp.CertPEM, keyPEM, nil)
}

func (c *Client) handleResponse(msg *Message) {
	c.pendingMu.Lock()
	ch, ok := c.pending[msg.ID]
	c.pendingMu.Unlock()

	if !ok {
		return
	}

	select {
	case ch <- msg:
	default:
	}
}

func (c *Client) handleRequest(ctx context.Context, msg *Message) error {
	if c.handler == nil {
		return c.sendResponse(msg.ID, nil, "no handler")
	}

	// Create ack callback that sends an Ack message.
	var ack Ack = func(ctx context.Context) error {
		ackMsg := &Message{
			ID:     msg.ID,
			Action: ActionAck,
		}
		c.sendMu.Lock()
		err := c.enc.Encode(ackMsg)
		c.sendMu.Unlock()
		return err
	}

	var buf bytes.Buffer
	err := c.handler(ctx, msg, &buf, ack)

	resp := &Message{
		ID:     msg.ID,
		Action: ActionResponse,
	}
	if err != nil {
		resp.Error = err.Error()
	} else if buf.Len() > 0 {
		resp.Payload = buf.Bytes()
	}

	c.sendMu.Lock()
	encErr := c.enc.Encode(resp)
	c.sendMu.Unlock()
	return encErr
}

func (c *Client) sendResponse(id MessageID, payload []byte, errMsg string) error {
	resp := &Message{
		ID:      id,
		Action:  ActionResponse,
		Payload: payload,
		Error:   errMsg,
	}

	c.sendMu.Lock()
	err := c.enc.Encode(resp)
	c.sendMu.Unlock()
	return err
}

// doProvisioning handles the provisioning protocol on an existing stream.
// The provision token is validated via TLS SNI during the handshake, not in this request.
func doProvisioning(ctx context.Context, stream *quic.Stream, auth CredentialStore) error {
	// Create CSR for the permanent hostname.
	csrPEM, keyPEM, err := CreateCSR(auth.Hostname())
	if err != nil {
		return err
	}

	enc := cbor.NewEncoder(stream)
	dec := cbor.NewDecoder(stream)

	// Send provisioning request.
	req := &Message{
		ID:     1,
		Action: ActionRequest,
		Target: System(),
		Type:   "provision-csr",
	}
	req.Payload, err = cbor.Marshal(ProvisionRequest{
		Hostname: auth.Hostname(),
		CSRPEM:   csrPEM,
	})
	if err != nil {
		return err
	}

	if err := enc.Encode(req); err != nil {
		return err
	}

	// Wait for response.
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		return err
	}

	if resp.Error != "" {
		return &RequestError{Message: resp.Error}
	}

	var provResp ProvisionResponse
	if err := cbor.Unmarshal(resp.Payload, &provResp); err != nil {
		return err
	}

	// Save credentials via auth manager.
	return auth.SaveCredentials(provResp.CertPEM, keyPEM, provResp.RootCAPEM)
}
