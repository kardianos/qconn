package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"github.com/quic-go/quic-go"
)

// Client implements the resilient QUIC client.
type Client struct {
	opt ClientOpt

	mu                 sync.RWMutex
	conn               *quic.Conn
	identity           qdef.Identity
	lastAddr           string
	cancel             context.CancelFunc
	shutdownWg         sync.WaitGroup
	lastRenewalAttempt time.Time
	nextID             int64
	Router             qdef.StreamRouter
}

type ClientOpt struct {
	ServerHostname  string
	CredentialStore CredentialStore
	Resolver        Resolver
	Handler         qdef.StreamHandler
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
	return &Client{
		opt: opt,
	}
}

func (c *Client) logf(format string, v ...interface{}) {
	if c.opt.Observer != nil {
		c.opt.Observer.Logf(c.identity, format, v...)
	}
}

// SetResolver sets the resolver for the client.
func (c *Client) SetResolver(r Resolver) {
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

func (c *Client) notifyState(state qdef.ClientState) {
	if c.opt.Observer != nil {
		c.opt.Observer.OnStateChange(c.identity, state)
	}
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
	host, _, err := net.SplitHostPort(c.opt.ServerHostname)
	if err != nil {
		return c.opt.ServerHostname
	}
	return host
}

func (c *Client) runProvisioning(ctx context.Context) error {
	c.notifyState(qdef.StateProvisioning)
	pt := c.opt.CredentialStore.ProvisionToken()
	if pt == "" {
		return fmt.Errorf("failed to get provision token: empty")
	}
	provCA, err := qdef.GenerateDerivedCA(pt)
	if err != nil {
		return fmt.Errorf("failed to generate derived CA: %w", err)
	}

	provCert, err := qdef.GenerateProvisioningIdentity(provCA)
	if err != nil {
		return fmt.Errorf("failed to generate provisioning identity: %w", err)
	}

	rootCAs, err := c.opt.CredentialStore.GetRootCAs()
	if err != nil {
		return fmt.Errorf("failed to get root CAs: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{provCert},
		RootCAs:      rootCAs,
		ServerName:   c.getServerName(),
	}

	addr, err := c.opt.Resolver.Resolve(ctx, c.opt.ServerHostname)
	if err != nil {
		return fmt.Errorf("failed to resolve server: %w", err)
	}

	conn, err := quic.DialAddr(ctx, addr.String(), tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("failed to dial server for provisioning: %w", err)
	}
	defer conn.CloseWithError(0, "provisioning done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open provisioning stream: %w", err)
	}
	defer stream.Close()

	id, err := c.opt.CredentialStore.GetIdentity()
	if err != nil {
		return fmt.Errorf("failed to get identity: %w", err)
	}

	rawPayload, _ := cbor.Marshal(id)
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

	if err := c.opt.CredentialStore.SaveCredentials(id, payload.CertPEM, payload.KeyPEM); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	return nil
}

func (c *Client) runRenewal(ctx context.Context) error {
	var payload qdef.CredentialResponse
	if _, err := c.Request(ctx, qdef.Addr{
		Service: qdef.ServiceSystem,
		Type:    "renew",
	}, nil, &payload); err != nil {
		return err
	}
	id, err := c.opt.CredentialStore.GetIdentity()
	if err != nil {
		return err
	}
	return c.opt.CredentialStore.SaveCredentials(id, payload.CertPEM, payload.KeyPEM)
}

// SetDevices updates the client's internal list of supported device types.
func (c *Client) SetDevices(devices []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.identity.Devices = devices
}

func (c *Client) TriggerUpdateDevices(ctx context.Context) error {
	c.mu.RLock()
	myDevices := c.identity.Devices
	c.mu.RUnlock()
	id, err := c.opt.CredentialStore.GetIdentity()
	if err != nil {
		return err
	}
	req := qdef.DeviceUpdateRequest{
		Type:    id.Type,
		Devices: myDevices,
	}
	target := qdef.Addr{
		Service: qdef.ServiceSystem,
		Type:    "devices",
	}

	_, err = c.Request(ctx, target, req, nil)
	if err != nil {
		return err
	}
	return nil
}

// Request is a high-level helper that handles ID generation, stream management, and CBOR abstraction.
func (c *Client) Request(ctx context.Context, target qdef.Addr, payload interface{}, response interface{}) (qdef.MessageID, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil || conn.Context().Err() != nil {
		return 0, fmt.Errorf("client not connected")
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

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

	if response != nil || true { // Always decode to check for Error
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
					c.notifyState(qdef.StateProvisioned)
					// Reload tlsConfig immediately.
					tlsConfig, _ = c.getTLSConfig()
				}
			} else {
				c.logf("qconn: could not load client credentials: %v", err)
			}
		}

		// 2. We have a valid config, try to connect.
		if tlsConfig != nil {
			if c.identity.Fingerprint == "" && len(tlsConfig.Certificates) > 0 {
				leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
				if err == nil {
					c.identity.Hostname = leaf.Subject.CommonName
					c.identity.Fingerprint = fmt.Sprintf("%x", qdef.Fingerprint(leaf.Raw))
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
				c.notifyState(qdef.StateDisconnected)
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
			_ = c.TriggerUpdateDevices(ctx)

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
					c.notifyState(qdef.StateDisconnected)
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
		c.notifyState(qdef.StateDisconnected)
	}

	addr, err := c.opt.Resolver.Resolve(ctx, c.opt.ServerHostname)
	if err != nil {
		c.logf("qconn: initial resolve failed: %v", err)
		return
	}
	c.lastAddr = addr.String()

	c.notifyState(qdef.StateConnecting)
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
	c.notifyState(qdef.StateConnected)
	c.logf("qconn: connection established to %s", c.lastAddr)
	if c.opt.Handler != nil {
		go c.opt.Handler.OnConnect(conn)
		go c.acceptLoop(ctx, conn)
	}
}

func (c *Client) acceptLoop(ctx context.Context, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(stream qdef.Stream) {
			dec := cbor.NewDecoder(stream)
			var msg qdef.Message
			if err := dec.Decode(&msg); err != nil {
				return
			}
			c.mu.RLock()
			id := c.identity
			c.mu.RUnlock()

			if c.Router.Dispatch(ctx, id, msg, stream) {
				return
			}

			if c.opt.Handler != nil {
				c.opt.Handler.Handle(ctx, id, msg, stream)
			}
		}(stream)
	}
}
