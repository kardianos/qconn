package qc

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

// InMemoryAuthorizationManager is a test implementation of AuthorizationManager.
type InMemoryAuthorizationManager struct {
	mu      sync.RWMutex
	clients map[string]ClientStatus
	CA      *InMemoryCA
}

func NewInMemoryAuthorizationManager() *InMemoryAuthorizationManager {
	ca, _ := NewInMemoryCA()
	return &InMemoryAuthorizationManager{
		clients: make(map[string]ClientStatus),
		CA:      ca,
	}
}
func (m *InMemoryAuthorizationManager) GetStatus(cert *x509.Certificate) (ClientStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status, ok := m.clients[cert.Subject.CommonName]
	if !ok {
		return StatusRevoked, nil
	}
	return status, nil
}
func (m *InMemoryAuthorizationManager) SetStatus(id Identity, status ClientStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[id.Hostname] = status
	return nil
}
func (m *InMemoryAuthorizationManager) IssueClientCertificate(id *Identity) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[id.Hostname] = StatusUnauthorized
	certPEM, keyPEM, err := m.CA.IssueClientCertificate(*id)
	if err == nil {
		// Update fingerprint in the identity.
		leaf, _ := x509.ParseCertificate(certPEM)
		if leaf != nil {
			id.Fingerprint = fmt.Sprintf("%x", Fingerprint(leaf.Raw))
		}
	}
	return certPEM, keyPEM, err
}
func (m *InMemoryAuthorizationManager) Revoke(id Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[id.Hostname] = StatusRevoked
	return nil
}
func (m *InMemoryAuthorizationManager) RootCert() *x509.Certificate { return m.CA.RootCert() }

func (m *InMemoryAuthorizationManager) IssueServerCertificate(id Identity) (tls.Certificate, error) {
	return m.CA.IssueServerCertificate(id)
}

// InMemoryCA is a helper for issuing certificates in tests.
type InMemoryCA struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func NewInMemoryCA() (*InMemoryCA, error) {
	cert, key, err := CreateCA()
	if err != nil {
		return nil, err
	}
	return &InMemoryCA{caCert: cert, caKey: key}, nil
}
func (ca *InMemoryCA) IssueClientCertificate(id Identity) ([]byte, []byte, error) {
	return CreateCert(ca.caCert, ca.caKey, id.Hostname, false)
}
func (ca *InMemoryCA) IssueServerCertificate(id Identity) (tls.Certificate, error) {
	certPEM, keyPEM, err := CreateCert(ca.caCert, ca.caKey, id.Hostname, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
func (ca *InMemoryCA) RootCert() *x509.Certificate { return ca.caCert }

// InMemoryCredentialStore is a test implementation of CredentialStore.
type InMemoryCredentialStore struct {
	identity       Identity
	provisionToken string
	certPEM        []byte
	keyPEM         []byte
	rootCACert     *x509.Certificate
}

func (s *InMemoryCredentialStore) GetIdentity() (Identity, error) {
	return s.identity, nil
}
func (s *InMemoryCredentialStore) ProvisionToken() (string, error) { return s.provisionToken, nil }
func (s *InMemoryCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	if len(s.certPEM) == 0 {
		return tls.Certificate{}, ErrCredentialsMissing
	}
	return tls.X509KeyPair(s.certPEM, s.keyPEM)
}
func (s *InMemoryCredentialStore) GetRootCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AddCert(s.rootCACert)
	return pool, nil
}
func (s *InMemoryCredentialStore) SaveCredentials(id Identity, certPEM, keyPEM []byte) error {
	s.identity, s.certPEM, s.keyPEM = id, certPEM, keyPEM
	return nil
}

// MockResolver is a test implementation of Resolver.
type MockResolver struct {
	mu   sync.RWMutex
	addr string
}

func (r *MockResolver) Resolve(_ context.Context, _ string) (net.Addr, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.addr == "" {
		return nil, errors.New("no address configured")
	}
	return net.ResolveUDPAddr("udp", r.addr)
}
func (r *MockResolver) SetAddress(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addr = addr
}

// TestStreamHandler is a test implementation of StreamHandler.
type TestStreamHandler struct {
	t            *testing.T
	Connects     chan *quic.Conn
	ReceivedData chan string
	DataToSend   chan string
	mu           sync.Mutex
}

func NewTestStreamHandler(t *testing.T) *TestStreamHandler {
	return &TestStreamHandler{
		t:            t,
		Connects:     make(chan *quic.Conn, 5),
		ReceivedData: make(chan string, 10),
		DataToSend:   make(chan string, 10),
	}
}
func (h *TestStreamHandler) Handle(ctx context.Context, stream *quic.Stream) {
	h.t.Log("Server handling new stream")
	go h.sendLoop(ctx, stream)

	dec := cbor.NewDecoder(stream)
	h.t.Log("Server decoder started")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		h.t.Log("Server attempting to decode")
		var msg string
		if err := dec.Decode(&msg); err != nil {
			h.t.Logf("Server decode error: %v", err)
			return // Stream closed.
		}
		h.t.Logf("Server decoded msg: %s", msg)
		h.ReceivedData <- msg
	}
}
func (h *TestStreamHandler) OnConnect(conn *quic.Conn) {
	h.Connects <- conn
}
func (h *TestStreamHandler) sendLoop(ctx context.Context, stream *quic.Stream) {
	h.t.Log("Server sendLoop started")
	enc := cbor.NewEncoder(stream)
	for msg := range h.DataToSend {
		select {
		case <-ctx.Done():
			return
		default:
		}
		h.t.Logf("Server sending msg: %s", msg)
		if err := enc.Encode(msg); err != nil {
			h.t.Logf("test handler failed to send: %v", err)
			return
		}
	}
}
func (h *TestStreamHandler) Close() { close(h.DataToSend) }

// TestObserver is a test implementation of ClientObserver.
type TestObserver struct {
	ctx    context.Context
	t      *testing.T
	States chan ClientState
	Logs   chan string
}

func NewTestObserver(ctx context.Context, t *testing.T) *TestObserver {
	return &TestObserver{
		ctx:    ctx,
		t:      t,
		States: make(chan ClientState, 100),
		Logs:   make(chan string, 100),
	}
}

func (o *TestObserver) OnStateChange(id Identity, state ClientState) {
	select {
	case <-o.ctx.Done():
		return
	default:
	}
	now := time.Now()
	second := now.Second()
	milli := now.Nanosecond() / 1e6
	o.t.Logf("%d.%d: State change [%s/%s]: %s", second, milli, id.Hostname, id.Fingerprint, state)
	o.States <- state
}

func (o *TestObserver) Logf(id Identity, format string, v ...interface{}) {
	select {
	case <-o.ctx.Done():
		return
	default:
	}
	msg := fmt.Sprintf(format, v...)
	now := time.Now()
	second := now.Second()
	milli := now.Nanosecond() / 1e6
	o.t.Logf("%d.%d: Log [%s/%s]: %s", second, milli, id.Hostname, id.Fingerprint, msg)
	o.Logs <- msg
}

// InterceptingPacketConn wraps a net.PacketConn and allows blocking reads/writes.
type InterceptingPacketConn struct {
	net.PacketConn
	mu           sync.RWMutex
	blockReads   bool
	blockWrites  bool
	readBarrier  chan struct{}
	writeBarrier chan struct{}
}

func NewInterceptingPacketConn(conn net.PacketConn) *InterceptingPacketConn {
	return &InterceptingPacketConn{
		PacketConn:   conn,
		readBarrier:  make(chan struct{}),
		writeBarrier: make(chan struct{}),
	}
}

func (c *InterceptingPacketConn) BlockReads(block bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockReads = block
}

func (c *InterceptingPacketConn) BlockWrites(block bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockWrites = block
}

func (c *InterceptingPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.mu.RLock()
	block := c.blockReads
	c.mu.RUnlock()

	if block {
		<-c.readBarrier // Block until closed or context cancelled (if we had it here).
		return 0, nil, fmt.Errorf("read blocked")
	}
	return c.PacketConn.ReadFrom(p)
}

func (c *InterceptingPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.RLock()
	block := c.blockWrites
	c.mu.RUnlock()

	if block {
		return len(p), nil // Silently drop.
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *InterceptingPacketConn) Close() error {
	// Only close once.
	select {
	case <-c.readBarrier:
	default:
		close(c.readBarrier)
	}
	select {
	case <-c.writeBarrier:
	default:
		close(c.writeBarrier)
	}
	return c.PacketConn.Close()
}
