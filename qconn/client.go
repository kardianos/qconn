package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qstate"
	"github.com/quic-go/quic-go"
)

var clientTransitions = []qstate.Transition[qdef.ClientState]{
	// From Disconnected
	{From: qdef.StateDisconnected, To: qdef.StateProvisioning, Name: "start_provision"},
	{From: qdef.StateDisconnected, To: qdef.StateConnecting, Name: "start_connect"},

	// From Provisioning
	{From: qdef.StateProvisioning, To: qdef.StateProvisioning, Name: "provision_retry"},
	{From: qdef.StateProvisioning, To: qdef.StateProvisioned, Name: "provision_success"},
	{From: qdef.StateProvisioning, To: qdef.StateDisconnected, Name: "provision_failure"},

	// From Provisioned
	{From: qdef.StateProvisioned, To: qdef.StateConnecting, Name: "connect_after_provision"},
	{From: qdef.StateProvisioned, To: qdef.StateDisconnected, Name: "provision_reset"},

	// From Connecting
	{From: qdef.StateConnecting, To: qdef.StateConnecting, Name: "connection_retry"},
	{From: qdef.StateConnecting, To: qdef.StateConnected, Name: "connection_established"},
	{From: qdef.StateConnecting, To: qdef.StateDisconnected, Name: "connection_failed"},

	// From Connected
	{From: qdef.StateConnected, To: qdef.StateAuthorized, Name: "authorized"},
	{From: qdef.StateConnected, To: qdef.StateDisconnected, Name: "connection_lost"},

	// From Authorized
	{From: qdef.StateAuthorized, To: qdef.StateRenewing, Name: "start_renewal"},
	{From: qdef.StateAuthorized, To: qdef.StateDisconnected, Name: "connection_lost"},

	// From Renewing
	{From: qdef.StateRenewing, To: qdef.StateAuthorized, Name: "renewal_complete"},
	{From: qdef.StateRenewing, To: qdef.StateDisconnected, Name: "renewal_failed_disconnect"},
}

// Client implements the resilient QUIC client.
type Client struct {
	opt      ClientOpt
	state    *qstate.Machine[qdef.ClientState]
	hostname string

	mu                 sync.RWMutex
	conn               *quic.Conn
	identity           qdef.Identity
	devices            []qdef.DeviceInfo // Rich device info for updates
	lastAddr           string
	cancel             context.CancelFunc
	shutdownWg         sync.WaitGroup
	lastRenewalAttempt time.Time
	nextID             int64
	Router             qdef.StreamRouter
}

type ClientOpt struct {
	// ServerHostname is the server address in "host:port" format.
	// Used for DNS resolution and connection.
	ServerHostname string

	// ServerName is the expected TLS server name for certificate verification.
	// This MUST match the hostname in the server's certificate (CN or SAN).
	// If empty, defaults to the host portion of ServerHostname.
	//
	// Use this when connecting via IP address or localhost but the server
	// certificate uses a different hostname.
	ServerName string

	// ClientHostname is the client's hostname used during provisioning.
	// If empty, falls back to the hostname from CredentialStore.GetIdentity().
	ClientHostname string

	// Roles are the roles this client requests during provisioning.
	// These determine what the client is authorized to do once approved.
	Roles []string

	CredentialStore qdef.CredentialStore
	Resolver        qdef.Resolver
	ResolverRefresh time.Duration
	Observer        qdef.ClientObserver
	KeepAlivePeriod time.Duration
	RenewWindow     time.Duration // Time before expiration to renew (default 15 days)
	CertValidity    time.Duration // Default certificate validity (not used by client directly but useful for testing)
	DialTimeout     time.Duration
}

// NewClient creates a new QUIC client.
func NewClient(opt ClientOpt) *Client {
	if opt.ResolverRefresh == 0 {
		opt.ResolverRefresh = 5 * time.Minute
	}

	hostname := opt.ClientHostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	var c *Client
	c = &Client{
		opt:      opt,
		hostname: hostname,
		state: qstate.New(
			qdef.StateDisconnected,
			clientTransitions,
			func(from, to qdef.ClientState, name string) {
				if c.opt.Observer != nil {
					c.opt.Observer.OnStateChange(c.identity, to)
				}
			},
		),
	}
	return c
}

func (c *Client) logf(format string, v ...any) {
	if c.opt.Observer != nil {
		c.opt.Observer.Logf(c.identity, format, v...)
	}
}

// SetResolver sets the resolver for the client.
func (c *Client) SetResolver(r qdef.Resolver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opt.Resolver = r
}

// SetObserver sets the observer for the client.
func (c *Client) SetObserver(o qdef.ClientObserver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opt.Observer = o
}

// Connect starts the client and its connection supervisor.
func (c *Client) getNextID() qdef.MessageID {
	return qdef.MessageID(atomic.AddInt64(&c.nextID, 1))
}

func (c *Client) Connect(ctx context.Context) error {
	ctx, c.cancel = context.WithCancel(ctx)

	c.shutdownWg.Add(1)
	go c.supervisor(ctx)
	return nil
}

func (c *Client) getTLSConfig() (*tls.Config, error) {
	tlsCert, err := c.opt.CredentialStore.GetClientCertificate()
	if err != nil {
		return nil, err
	}

	rootCAs, err := c.opt.CredentialStore.GetRootCAs()
	if err != nil {
		return nil, fmt.Errorf("qconn: could not load root CA: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		ServerName:   c.getServerName(),
	}, nil
}

func (c *Client) getServerName() string {
	if c.opt.ServerName != "" {
		return c.opt.ServerName
	}
	host, _, err := net.SplitHostPort(c.opt.ServerHostname)
	if err != nil {
		return c.opt.ServerHostname
	}
	return host
}

func (c *Client) runProvisioning(ctx context.Context) error {
	c.state.MustTransitionTo(qdef.StateProvisioning)
	pt := c.opt.CredentialStore.ProvisionToken()
	if pt == "" {
		return qdef.ErrProvisionTokenEmpty
	}
	provCA, err := qdef.GenerateDerivedCA(pt)
	if err != nil {
		return fmt.Errorf("failed to generate derived CA: %w", err)
	}

	provCert, err := qdef.GenerateProvisioningIdentity(provCA)
	if err != nil {
		return fmt.Errorf("failed to generate provisioning identity: %w", err)
	}

	// During provisioning, use the derived CA to verify the server.
	// The server must present a certificate signed by the same derived CA.
	provCACert, err := x509.ParseCertificate(provCA.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse provisioning CA: %w", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(provCACert)

	// Use a deterministic server name derived from the token.
	// This allows the server to select the correct provisioning certificate.
	provServerName := qdef.ProvisioningServerName(pt)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{provCert},
		RootCAs:      rootCAs,
		ServerName:   provServerName,
	}

	addr, err := c.opt.Resolver.Resolve(ctx, c.opt.ServerHostname)
	if err != nil {
		return fmt.Errorf("failed to resolve server: %w", err)
	}

	conn, err := quic.DialAddr(ctx, addr.String(), tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("failed to dial server for provisioning: %w", err)
	}
	defer func() { _ = conn.CloseWithError(0, "provisioning done") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open provisioning stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	// Use roles from ClientOpt (may be nil/empty).
	roles := c.opt.Roles

	// Generate CSR locally - private key never leaves the client.
	csrPEM, keyPEM, err := qdef.CreateCSR(c.hostname)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	req := qdef.ProvisioningRequest{
		Hostname: c.hostname,
		CSRPEM:   csrPEM,
		Roles:    roles,
	}
	rawPayload, err := cbor.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal provisioning request: %w", err)
	}
	msg := qdef.Message{
		ID: c.getNextID(),
		Target: qdef.Addr{
			Service: qdef.ServiceProvision,
		},
		Payload: rawPayload,
	}

	if err := cbor.NewEncoder(stream).Encode(msg); err != nil {
		return fmt.Errorf("failed to encode provisioning request: %w", err)
	}

	var resp qdef.Message
	if err := cbor.NewDecoder(stream).Decode(&resp); err != nil {
		return fmt.Errorf("failed to decode provisioning response: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("provisioning error: %s", resp.Error)
	}

	var payload qdef.CredentialResponse
	if err := cbor.Unmarshal(resp.Payload, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal provisioning payload: %w", err)
	}

	// Save root CA if provided (for future server verification).
	if len(payload.RootCAPEM) > 0 {
		if err := c.opt.CredentialStore.SetRootCA(payload.RootCAPEM); err != nil {
			return fmt.Errorf("failed to save root CA: %w", err)
		}
	}

	// Save credentials with locally-generated private key.
	if err := c.opt.CredentialStore.SaveCredentials(payload.CertPEM, keyPEM); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	return nil
}

func (c *Client) runRenewal(ctx context.Context) error {
	id, err := c.opt.CredentialStore.GetIdentity()
	if err != nil {
		return err
	}

	// Generate new CSR locally - private key never leaves the client.
	csrPEM, keyPEM, err := qdef.CreateCSR(id.Hostname)
	if err != nil {
		return fmt.Errorf("failed to create CSR for renewal: %w", err)
	}

	req := qdef.RenewalRequest{
		CSRPEM: csrPEM,
	}

	var payload qdef.CredentialResponse
	if _, err := c.Request(ctx, qdef.Addr{
		Service: qdef.ServiceSystem,
		Type:    "renew",
	}, req, &payload); err != nil {
		return err
	}

	// Save credentials with locally-generated private key.
	return c.opt.CredentialStore.SaveCredentials(payload.CertPEM, keyPEM)
}

// SetDevices updates the client's internal list of devices.
// Each device includes its ID, name, service type, device type, and serial number.
func (c *Client) SetDevices(devices []qdef.DeviceInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices = devices
}

// TriggerUpdateDevices sends the device list to the server.
func (c *Client) TriggerUpdateDevices(ctx context.Context) error {
	c.mu.RLock()
	devices := c.devices
	localAddr := c.conn.LocalAddr()
	c.mu.RUnlock()

	addr := localAddr.(*net.UDPAddr).AddrPort().Addr()

	req := qdef.DeviceUpdateRequest{
		Hostname:  c.hostname,
		LocalAddr: addr,
		Devices:   devices,
	}
	target := qdef.Addr{
		Service: qdef.ServiceSystem,
		Type:    "devices",
	}

	_, err := c.Request(ctx, target, req, nil)
	if err != nil {
		return err
	}

	// Successful device update means the server has authorized client.
	// Transition to Authorized state if we're currently Connected.
	if c.state.Current() == qdef.StateConnected {
		_ = c.state.TransitionTo(qdef.StateAuthorized)
	}
	return nil
}

// Request is a high-level helper that handles ID generation, stream management, and CBOR abstraction.
func (c *Client) Request(ctx context.Context, target qdef.Addr, payload any, response any) (qdef.MessageID, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil || conn.Context().Err() != nil {
		return 0, qdef.ErrNotConnected
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = stream.Close() }()

	var rawPayload []byte
	if payload != nil {
		rawPayload, err = cbor.Marshal(payload)
		if err != nil {
			return 0, err
		}
	}

	msgID := c.getNextID()
	msg := qdef.Message{
		ID:      msgID,
		Target:  target,
		Payload: rawPayload,
	}

	if err := cbor.NewEncoder(stream).Encode(msg); err != nil {
		return msgID, err
	}

	// Always decode response to check for errors from the server.
	var respMsg qdef.Message
	if err := cbor.NewDecoder(stream).Decode(&respMsg); err != nil {
		return msgID, err
	}
	if respMsg.Error != "" {
		return msgID, errors.New(respMsg.Error)
	}
	if response != nil {
		if err := cbor.Unmarshal(respMsg.Payload, response); err != nil {
			return msgID, err
		}
	}

	return msgID, nil
}

// Connection returns the current active connection. It may be nil.
func (c *Client) Connection() *quic.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// Close gracefully shuts down the client.
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	c.shutdownWg.Wait()
}

func (c *Client) supervisor(ctx context.Context) {
	defer c.shutdownWg.Done()

	resolveTicker := time.NewTicker(c.opt.ResolverRefresh)
	defer resolveTicker.Stop()

	// Periodic check for renewal and device updates.
	// Default to 10 seconds to be reasonably responsive.
	checkTicker := time.NewTicker(10 * time.Second)
	if c.opt.KeepAlivePeriod > 0 && c.opt.KeepAlivePeriod < 10*time.Second {
		checkTicker.Reset(c.opt.KeepAlivePeriod)
	}
	defer checkTicker.Stop()

	for {
		// 1. Ensure we have valid TLS config (provision if needed).
		tlsConfig, err := c.getTLSConfig()
		if err != nil {
			if errors.Is(err, qdef.ErrCredentialsMissing) {
				c.logf("qconn: credentials missing, attempting provisioning")
				if provErr := c.runProvisioning(ctx); provErr != nil {
					c.logf("qconn: provisioning failed: %v", provErr)
				} else {
					c.state.MustTransitionTo(qdef.StateProvisioned)
					// Reload tlsConfig immediately.
					tlsConfig, _ = c.getTLSConfig()
				}
			} else {
				c.logf("qconn: could not load client credentials: %v", err)
			}
		}

		// 2. We have a valid config, try to connect.
		if tlsConfig != nil {
			if c.identity.Fingerprint.IsZero() && len(tlsConfig.Certificates) > 0 {
				leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
				if err == nil {
					c.identity.Hostname = leaf.Subject.CommonName
					c.identity.Fingerprint = qdef.FingerprintOf(leaf)
				}
			}
			c.attemptConnect(ctx, tlsConfig)
		}

		var connDone <-chan struct{}
		c.mu.RLock()
		if c.conn != nil {
			connDone = c.conn.Context().Done()
		}
		c.mu.RUnlock()

		// Triggers
		credUpdate := c.opt.CredentialStore.OnUpdate()
		resolveUpdate := c.opt.Resolver.OnUpdate(c.opt.ServerHostname)

		select {
		case <-connDone:
			// Connection lost, loop around to reconnect.
			c.logf("qconn: connection lost")
		case <-credUpdate:
			c.logf("qconn: credentials updated")
		case <-resolveUpdate:
			c.logf("qconn: resolver updated")
		case <-ctx.Done():
			c.mu.Lock()
			if c.conn != nil {
				_ = c.conn.CloseWithError(0, "client shutting down")
				c.state.MustTransitionTo(qdef.StateDisconnected)
			}
			c.mu.Unlock()
			return
		case <-checkTicker.C:
			// Check renewal.
			if tlsConfig != nil && len(tlsConfig.Certificates) > 0 {
				leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
				if err == nil {
					window := c.opt.RenewWindow
					if window == 0 {
						window = 15 * 24 * time.Hour
					}
					now := time.Now()
					if now.After(leaf.NotAfter.Add(-window)) {
						c.mu.Lock()
						lastAttempt := c.lastRenewalAttempt
						c.mu.Unlock()

						if now.Sub(lastAttempt) > 1*time.Minute {
							c.logf("qconn: certificate expiring soon, attempting renewal")
							c.mu.Lock()
							c.lastRenewalAttempt = now
							c.mu.Unlock()

							if err := c.runRenewal(ctx); err != nil {
								c.logf("qconn: renewal failed: %v", err)
							} else {
								c.logf("qconn: certificate renewed successfully")
							}
						}
					}
				}
			}

			// Periodic device update.
			if err := c.TriggerUpdateDevices(ctx); err != nil {
				c.logf("qconn: TriggerUpdateDevices: %v", err)
			}

		case <-resolveTicker.C:
			addr, err := c.opt.Resolver.Resolve(ctx, c.opt.ServerHostname)
			if err != nil {
				c.logf("qconn: supervisor DNS resolve failed: %v", err)
				continue
			}
			nextAddr := addr.String()

			c.mu.Lock()
			if nextAddr != c.lastAddr {
				c.logf("qconn: supervisor resolved new address: %s (old: %s)", nextAddr, c.lastAddr)
				c.lastAddr = nextAddr
				if c.conn != nil {
					_ = c.conn.CloseWithError(0, "address changed")
					c.state.MustTransitionTo(qdef.StateDisconnected)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *Client) attemptConnect(ctx context.Context, tlsConfig *tls.Config) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Don't reconnect if the context is already cancelled.
	if ctx.Err() != nil {
		return
	}

	if c.conn != nil {
		if c.conn.Context().Err() == nil {
			return // Already connected.
		}
		c.state.MustTransitionTo(qdef.StateDisconnected)
	}

	addr, err := c.opt.Resolver.Resolve(ctx, c.opt.ServerHostname)
	if err != nil {
		c.logf("qconn: initial resolve failed: %v", err)
		return
	}
	c.lastAddr = addr.String()

	c.state.MustTransitionTo(qdef.StateConnecting)
	c.logf("qconn: attempting to connect to %s", c.lastAddr)

	dto := c.opt.DialTimeout
	if dto == 0 {
		dto = 5 * time.Second
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, dto)
	defer dialCancel()

	kap := c.opt.KeepAlivePeriod
	if kap == 0 {
		kap = DefaultKeepAlivePeriod
	}
	qc := &quic.Config{
		KeepAlivePeriod: kap,
		MaxIdleTimeout:  kap * 4,
	}

	conn, err := quic.DialAddr(dialCtx, c.lastAddr, tlsConfig, qc)
	if err != nil {
		c.logf("qconn: failed to dial %s: %v", c.lastAddr, err)
		return
	}

	c.conn = conn
	// Set the identity's address to the server we're connected to.
	if remoteAddr, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		c.identity.Address = remoteAddr
	}
	c.state.MustTransitionTo(qdef.StateConnected)
	c.logf("qconn: connection established to %s", c.lastAddr)

	// Start accepting incoming streams for bi-directional communication.
	go c.acceptLoop(ctx, conn)
}

func (c *Client) acceptLoop(ctx context.Context, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(stream *quic.Stream) {
			defer func() { _ = stream.Close() }()

			dec := qdef.NewDecoder(stream, 0) // Use default limit for client.
			var msg qdef.Message
			if err := dec.Decode(&msg); err != nil {
				return
			}
			c.mu.RLock()
			id := c.identity
			c.mu.RUnlock()

			// If we receive a request from the server, we must be authorized
			// (the server only routes to authorized clients).
			// Transition to Authorized state if needed.
			if c.state.Current() == qdef.StateConnected {
				_ = c.state.TransitionTo(qdef.StateAuthorized)
			}

			// Reject requests if not in an authorized state (e.g., still connecting).
			if c.state.Current() != qdef.StateAuthorized {
				errMsg := qdef.Message{
					ID:    msg.ID,
					Error: "client not authorized",
				}
				_ = cbor.NewEncoder(stream).Encode(errMsg)
				return
			}

			// Helper to send response.
			sendResponse := func(resp any, respErr error) {
				var respMsg qdef.Message
				respMsg.ID = msg.ID
				if respErr != nil {
					respMsg.Error = respErr.Error()
				} else {
					payload, err := cbor.Marshal(resp)
					if err != nil {
						c.logf("failed to marshal response for %s/%s: %v", msg.Target.Service, msg.Target.Type, err)
						respMsg.Error = fmt.Sprintf("failed to marshal response: %v", err)
					} else {
						respMsg.Payload = payload
					}
				}
				if encErr := cbor.NewEncoder(stream).Encode(respMsg); encErr != nil {
					c.logf("failed to encode response: %v", encErr)
				}
			}

			resp, err := c.Router.Dispatch(ctx, id, msg)
			if err == nil {
				sendResponse(resp, nil)
				return
			}

			// Send error response for unhandled messages.
			if errors.Is(err, qdef.ErrNoHandler) {
				sendResponse(nil, fmt.Errorf("no handler for %s:%s", msg.Target.Service, msg.Target.Type))
				return
			}

			// Log dispatch errors and send error response.
			c.logf("dispatch error for %s/%s: %v", msg.Target.Service, msg.Target.Type, err)
			sendResponse(nil, err)
		}(stream)
	}
}
