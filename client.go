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

// ClientAuthManager is an alias for CredentialStore for backwards compatibility.
// Deprecated: Use CredentialStore instead.
type ClientAuthManager = CredentialStore

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

	handler Handler

	done chan struct{}
}

// ClientOpt configures a Client.
type ClientOpt struct {
	// ServerAddr is the server address to connect to.
	// If Resolver is set, this is treated as a hostname to resolve.
	ServerAddr string

	// Auth manages client credentials.
	Auth ClientAuthManager

	// Handler processes incoming requests from other clients.
	Handler Handler

	// Resolver optionally resolves ServerAddr before connecting.
	// If nil, ServerAddr is used directly.
	Resolver Resolver

	// KeepalivePeriod sets the QUIC keepalive interval.
	KeepalivePeriod time.Duration
}

// NewClient creates and connects a new client.
// If Auth.NeedsProvisioning() returns true, provisions first then reconnects.
func NewClient(ctx context.Context, opt ClientOpt) (*Client, error) {
	if opt.Auth == nil {
		return nil, ErrNoCert
	}

	// Resolve server address if resolver is configured.
	serverAddr := opt.ServerAddr
	if opt.Resolver != nil {
		resolved, err := opt.Resolver.Resolve(ctx, opt.ServerAddr)
		if err != nil {
			return nil, err
		}
		serverAddr = resolved
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

	quicConn, err := quic.DialAddr(ctx, serverAddr, tlsCfg, quicConfig)
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
			resolved, err := opt.Resolver.Resolve(ctx, opt.ServerAddr)
			if err != nil {
				return nil, err
			}
			serverAddr = resolved
		}

		// Reconnect with new credentials.
		tlsCfg, err = opt.Auth.TLSConfig()
		if err != nil {
			return nil, err
		}

		quicConn, err = quic.DialAddr(ctx, serverAddr, tlsCfg, quicConfig)
		if err != nil {
			return nil, err
		}

		stream, err = quicConn.OpenStreamSync(ctx)
		if err != nil {
			quicConn.CloseWithError(1, "stream error")
			return nil, err
		}
	}

	c := &Client{
		quicConn: quicConn,
		stream:   stream,
		enc:      cbor.NewEncoder(stream),
		dec:      cbor.NewDecoder(stream),
		pending:  make(map[MessageID]chan *Message),
		handler:  opt.Handler,
		done:     make(chan struct{}),
	}

	go c.readLoop(ctx)

	return c, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	close(c.done)
	return c.quicConn.CloseWithError(0, "client closing")
}

// Request sends a request to a target and waits for response.
// The role parameter is used for RBAC authorization checks on the server.
// For system messages, role can be empty. For client-to-client messages with RBAC enabled,
// role is required.
func (c *Client) Request(ctx context.Context, target Target, typ string, role string, req, resp any) error {
	id := MessageID(c.nextID.Add(1))

	var payload []byte
	if req != nil {
		var err error
		payload, err = cbor.Marshal(req)
		if err != nil {
			return err
		}
	}

	msg := &Message{
		ID:      id,
		Action:  ActionRequest,
		Target:  target,
		Type:    typ,
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
	err := c.enc.Encode(msg)
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
			if err := c.handleRequest(ctx, &msg); err != nil {
				return
			}
		}
	}
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
func doProvisioning(ctx context.Context, stream *quic.Stream, auth ClientAuthManager) error {
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
