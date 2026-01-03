package qc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

var (
	// ErrCredentialsMissing is returned when the credential store has no valid client certificate.
	ErrCredentialsMissing = fmt.Errorf("qconn: credentials missing")
)

// Client implements the resilient QUIC client.
type Client struct {
	opt ClientOpt

	mu         sync.RWMutex
	conn       *quic.Conn
	identity   Identity
	lastAddr   string
	cancel     context.CancelFunc
	shutdownWg sync.WaitGroup
}

type ClientOpt struct {
	ServerHostname  string
	CredentialStore CredentialStore
	Resolver        Resolver
	Handler         StreamHandler
	ResolverRefresh time.Duration
	Observer        ClientObserver
	KeepAlivePeriod time.Duration
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

func (c *Client) notifyState(state ClientState) {
	if c.opt.Observer != nil {
		c.opt.Observer.OnStateChange(c.identity, state)
	}
}

// Connect starts the client and its connection supervisor.
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
		ServerName:   c.opt.ServerHostname,
	}, nil
}

func (c *Client) runProvisioning(ctx context.Context) error {
	c.notifyState(StateProvisioning)
	pt, err := c.opt.CredentialStore.ProvisionToken()
	if err != nil {
		return fmt.Errorf("failed to get provision token: %w", err)
	}
	provCA, err := GenerateDerivedCA(pt)
	if err != nil {
		return fmt.Errorf("failed to generate derived CA: %w", err)
	}

	provCert, err := GenerateProvisioningIdentity(provCA)
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
		ServerName:   c.opt.ServerHostname,
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

	if err := cbor.NewEncoder(stream).Encode(id); err != nil {
		return fmt.Errorf("failed to encode provisioning request: %w", err)
	}

	var resp struct {
		CertPEM []byte `json:"cert_pem"`
		KeyPEM  []byte `json:"key_pem"`
	}
	if err := cbor.NewDecoder(stream).Decode(&resp); err != nil {
		return fmt.Errorf("failed to decode provisioning response: %w", err)
	}

	if err := c.opt.CredentialStore.SaveCredentials(id, resp.CertPEM, resp.KeyPEM); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	return nil
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

	// Use a faster ticker for checking connection health when disconnected.
	checkTicker := time.NewTicker(1 * time.Second)
	defer checkTicker.Stop()

	for {
		// 1. Ensure we have valid TLS config (provision if needed).
		tlsConfig, err := c.getTLSConfig()
		if err != nil {
			if errors.Is(err, ErrCredentialsMissing) {
				c.logf("qconn: credentials missing, attempting provisioning")
				if provErr := c.runProvisioning(ctx); provErr != nil {
					c.logf("qconn: provisioning failed: %v", provErr)
				} else {
					c.notifyState(StateProvisioned)
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
					c.identity.Fingerprint = fmt.Sprintf("%x", Fingerprint(leaf.Raw))
				}
			}
			c.attemptConnect(ctx, tlsConfig)
		}

		select {
		case <-ctx.Done():
			c.mu.Lock()
			if c.conn != nil {
				_ = c.conn.CloseWithError(0, "client shutting down")
				c.notifyState(StateDisconnected)
			}
			c.mu.Unlock()
			return
		case <-checkTicker.C:
			// Just a pulse to trigger attemptConnect at the top of the loop.
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
					c.notifyState(StateDisconnected)
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
		c.notifyState(StateDisconnected)
	}

	addr, err := c.opt.Resolver.Resolve(ctx, c.opt.ServerHostname)
	if err != nil {
		c.logf("qconn: initial resolve failed: %v", err)
		return
	}
	c.lastAddr = addr.String()

	c.notifyState(StateConnecting)
	c.logf("qconn: attempting to connect to %s", c.lastAddr)
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
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
	c.notifyState(StateConnected)
	c.logf("qconn: connection established to %s", c.lastAddr)
	if c.opt.Handler != nil {
		go c.opt.Handler.OnConnect(conn)
	}
}
