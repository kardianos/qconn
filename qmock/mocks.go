package qmock

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kardianos/qconn/qdef"
	"github.com/quic-go/quic-go"
)

// InMemoryAuthorizationManager is a test implementation of AuthorizationManager.
type InMemoryAuthorizationManager struct {
	mu           sync.RWMutex
	clients      map[string]qdef.ClientStatus
	CA           *InMemoryCA
	serverCert   *tls.Certificate
	authorizeAll bool
	sigs         map[string]chan struct{}
}

func NewInMemoryAuthorizationManager() *InMemoryAuthorizationManager {
	ca, _ := NewInMemoryCA()
	return &InMemoryAuthorizationManager{
		clients: make(map[string]qdef.ClientStatus),
		CA:      ca,
		sigs:    make(map[string]chan struct{}),
	}
}

func (m *InMemoryAuthorizationManager) GetSignal(cert *x509.Certificate) <-chan struct{} {
	fp := qdef.FingerprintHex(cert)
	m.mu.Lock()
	defer m.mu.Unlock()
	sig, ok := m.sigs[fp]
	if !ok {
		sig = make(chan struct{})
		m.sigs[fp] = sig
	}
	return sig
}

func (m *InMemoryAuthorizationManager) trigger(fp string) {
	if sig, ok := m.sigs[fp]; ok {
		close(sig)
		delete(m.sigs, fp)
	}
}
func (m *InMemoryAuthorizationManager) GetStatus(cert *x509.Certificate) (qdef.ClientStatus, error) {
	fp := qdef.FingerprintHex(cert)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.authorizeAll {
		return qdef.StatusAuthorized, nil
	}
	status, ok := m.clients[fp]
	if !ok {
		return qdef.StatusRevoked, nil
	}
	return status, nil
}
func (m *InMemoryAuthorizationManager) AuthorizeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authorizeAll = true
	for k := range m.clients {
		m.clients[k] = qdef.StatusAuthorized
		m.trigger(k)
	}
}
func (m *InMemoryAuthorizationManager) SetStatus(id qdef.Identity, status qdef.ClientStatus) error {
	if id.Fingerprint.IsZero() {
		return fmt.Errorf("missing fingerprint")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fpStr := id.Fingerprint.String()
	m.clients[fpStr] = status
	m.trigger(fpStr)
	return nil
}
func (m *InMemoryAuthorizationManager) SignProvisioningCSR(csrPEM []byte, hostname string) ([]byte, error) {
	// Validate that CSR matches the claimed hostname to prevent identity spoofing.
	certPEM, err := qdef.SignCSRWithValidation(m.CA.caCert, m.CA.caKey, csrPEM, hostname, false)
	if err != nil {
		return nil, err
	}

	// Track the new client by fingerprint.
	block, _ := pem.Decode(certPEM)
	if block != nil {
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if leaf != nil {
			fp := qdef.FingerprintHex(leaf)
			m.mu.Lock()
			m.clients[fp] = qdef.StatusUnauthorized
			m.trigger(fp)
			m.mu.Unlock()
		}
	}

	return certPEM, nil
}

func (m *InMemoryAuthorizationManager) SignRenewalCSR(csrPEM []byte, fingerprint string) ([]byte, error) {
	// Verify the client exists and is authorized for renewal.
	m.mu.RLock()
	status, ok := m.clients[fingerprint]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: fingerprint %s", qdef.ErrUnknownClient, fingerprint)
	}
	if status == qdef.StatusRevoked {
		return nil, qdef.ErrClientRevoked
	}

	// We don't have the hostname here easily, so we first decode the CSR to get it.
	// In a real implementation, you'd look up the hostname by fingerprint.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	certPEM, err := qdef.SignCSRWithValidation(m.CA.caCert, m.CA.caKey, csrPEM, csr.Subject.CommonName, false)
	if err != nil {
		return nil, err
	}

	// Track the renewed client by new fingerprint.
	block, _ = pem.Decode(certPEM)
	if block != nil {
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if leaf != nil {
			newFP := qdef.FingerprintHex(leaf)
			m.mu.Lock()
			// Remove old fingerprint, add new one with same status.
			delete(m.clients, fingerprint)
			m.clients[newFP] = status
			m.trigger(newFP)
			m.mu.Unlock()
		}
	}

	return certPEM, nil
}
func (m *InMemoryAuthorizationManager) Revoke(id qdef.Identity) error {
	if id.Fingerprint.IsZero() {
		return errors.New("fingerprint is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fpStr := id.Fingerprint.String()
	m.clients[fpStr] = qdef.StatusRevoked
	m.trigger(fpStr)
	return nil
}
func (m *InMemoryAuthorizationManager) AuthorizeRoles(fingerprint string, requested []string) []string {
	// By default, mock allows all requested roles.
	return requested
}
func (m *InMemoryAuthorizationManager) RootCert() *x509.Certificate { return m.CA.RootCert() }

func (m *InMemoryAuthorizationManager) ServerCertificate() (tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.serverCert != nil {
		return *m.serverCert, nil
	}
	cert, err := m.CA.IssueServerCertificate(qdef.Identity{Hostname: "localhost"})
	if err != nil {
		return tls.Certificate{}, err
	}
	m.serverCert = &cert
	return cert, nil
}

func (m *InMemoryAuthorizationManager) IssueServerCertificate(id qdef.Identity) (tls.Certificate, error) {
	return m.CA.IssueServerCertificate(id)
}

// IssueClientCertificate is a test helper that creates a certificate for a client.
// This bypasses the CSR flow and is only for setting up test fixtures.
// In production, clients generate their own keys and send CSRs.
func (m *InMemoryAuthorizationManager) IssueClientCertificate(id *qdef.Identity) ([]byte, []byte, error) {
	certPEM, keyPEM, err := m.CA.IssueClientCertificate(*id)
	if err != nil {
		return nil, nil, err
	}

	// Update fingerprint in the identity.
	block, _ := pem.Decode(certPEM)
	if block != nil {
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if leaf != nil {
			id.Fingerprint = qdef.FingerprintOf(leaf)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	fpStr := id.Fingerprint.String()
	m.clients[fpStr] = qdef.StatusUnauthorized
	m.trigger(fpStr)

	return certPEM, keyPEM, nil
}

// InMemoryCA is a helper for issuing certificates in tests.
type InMemoryCA struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func NewInMemoryCA() (*InMemoryCA, error) {
	cert, key, err := qdef.CreateCA()
	if err != nil {
		return nil, err
	}
	return &InMemoryCA{caCert: cert, caKey: key}, nil
}
func (ca *InMemoryCA) IssueClientCertificate(id qdef.Identity) ([]byte, []byte, error) {
	return qdef.CreateCert(ca.caCert, ca.caKey, id.Hostname, false)
}
func (ca *InMemoryCA) IssueServerCertificate(id qdef.Identity) (tls.Certificate, error) {
	certPEM, keyPEM, err := qdef.CreateCert(ca.caCert, ca.caKey, id.Hostname, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
func (ca *InMemoryCA) RootCert() *x509.Certificate { return ca.caCert }

// InMemoryCredentialStore is a test implementation of CredentialStore.
type InMemoryCredentialStore struct {
	mu       sync.Mutex
	Identity qdef.Identity
	Token    string
	CertPEM  []byte
	KeyPEM   []byte
	RootCA   *x509.Certificate
	sig      chan struct{}
}

func (s *InMemoryCredentialStore) GetIdentity() (qdef.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Identity, nil
}

func (s *InMemoryCredentialStore) OnUpdate() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sig == nil {
		s.sig = make(chan struct{})
	}
	return s.sig
}
func (s *InMemoryCredentialStore) ProvisionToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Token
}
func (s *InMemoryCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.CertPEM) == 0 {
		return tls.Certificate{}, qdef.ErrCredentialsMissing
	}
	return tls.X509KeyPair(s.CertPEM, s.KeyPEM)
}
func (s *InMemoryCredentialStore) GetRootCAs() (*x509.CertPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pool := x509.NewCertPool()
	pool.AddCert(s.RootCA)
	return pool, nil
}
func (s *InMemoryCredentialStore) SaveCredentials(id qdef.Identity, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	block, _ := pem.Decode(certPEM)
	if block != nil {
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if leaf != nil {
			id.Fingerprint = qdef.FingerprintOf(leaf)
		}
	}

	s.Identity, s.CertPEM, s.KeyPEM = id, certPEM, keyPEM
	if s.sig != nil {
		close(s.sig)
		s.sig = nil
	}
	return nil
}
func (s *InMemoryCredentialStore) Renew(ctx context.Context) error {
	return nil
}

func (s *InMemoryCredentialStore) TestingLock(fn func(s *InMemoryCredentialStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// MockResolver is a test implementation of Resolver.
type MockResolver struct {
	mu   sync.RWMutex
	addr string
	sigs map[string]chan struct{}
}

func (r *MockResolver) Resolve(_ context.Context, _ string) (net.Addr, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.addr == "" {
		return nil, errors.New("no address configured")
	}
	return net.ResolveUDPAddr("udp", r.addr)
}

func (r *MockResolver) OnUpdate(hostname string) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sigs == nil {
		r.sigs = make(map[string]chan struct{})
	}
	sig, ok := r.sigs[hostname]
	if !ok {
		sig = make(chan struct{})
		r.sigs[hostname] = sig
	}
	return sig
}
func (r *MockResolver) SetAddress(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addr = addr
	for h, sig := range r.sigs {
		close(sig)
		delete(r.sigs, h)
	}
}

type mockResolver struct {
	addr string
}

func (r *mockResolver) Resolve(ctx context.Context, hostname string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", r.addr)
}

// TestStreamHandler is a test implementation of StreamHandler.
type TestStreamHandler struct {
	t            *testing.T
	Connects     chan *quic.Conn
	ReceivedData chan string
	DataToSend   chan string
	Auth         qdef.AuthorizationManager
	mu           sync.Mutex
}

func NewTestStreamHandler(t *testing.T) *TestStreamHandler {
	h := &TestStreamHandler{
		t:            t,
		Connects:     make(chan *quic.Conn, 5),
		ReceivedData: make(chan string, 10),
		DataToSend:   make(chan string, 10),
	}
	return h
}
func (h *TestStreamHandler) Handle(ctx context.Context, id qdef.Identity, msg qdef.Message, stream qdef.Stream) {
	h.t.Log("Server handling new stream (fallback)")
	h.t.Logf("Server: no handler for %s:%s", msg.Target.Service, msg.Target.Type)
}

func (h *TestStreamHandler) RegisterHandlers(r *qdef.StreamRouter) {
	qdef.Handle(r, qdef.ServiceUser, "", h.handleTestString)
}

func (h *TestStreamHandler) handleTestString(ctx context.Context, id qdef.Identity, req *string) (*string, error) {
	h.t.Logf("Server handled test string: %s", *req)
	h.ReceivedData <- *req

	select {
	case resp := <-h.DataToSend:
		return &resp, nil
	case <-time.After(100 * time.Millisecond):
		return nil, nil // No response for this test.
	}
}

func (h *TestStreamHandler) OnConnect(conn *quic.Conn) {
	h.Connects <- conn
}
func (h *TestStreamHandler) Close() { close(h.DataToSend) }

// TestObserver is a test implementation of ClientObserver.
type TestObserver struct {
	t      *testing.T
	States chan qdef.ClientState
	Logs   chan string
	mu     sync.Mutex
	done   bool
}

func NewTestObserver(ctx context.Context, t *testing.T) *TestObserver {
	o := &TestObserver{
		t:      t,
		States: make(chan qdef.ClientState, 100),
		Logs:   make(chan string, 100),
	}
	// Use t.Cleanup to set done synchronously when test ends.
	t.Cleanup(func() {
		o.mu.Lock()
		o.done = true
		o.mu.Unlock()
	})
	return o
}

func (o *TestObserver) OnStateChange(id qdef.Identity, state qdef.ClientState) {
	o.mu.Lock()
	if o.done {
		o.mu.Unlock()
		return
	}
	now := time.Now()
	second := now.Second()
	milli := now.Nanosecond() / 1e6
	o.t.Logf("%d.%d: State change [%s]: %s", second, milli, id, state)
	o.mu.Unlock()

	select {
	case o.States <- state:
	default:
	}
}

func (o *TestObserver) Logf(id qdef.Identity, format string, v ...interface{}) {
	o.mu.Lock()
	if o.done {
		o.mu.Unlock()
		return
	}
	msg := fmt.Sprintf(format, v...)
	now := time.Now()
	second := now.Second()
	milli := now.Nanosecond() / 1e6
	o.t.Logf("%d.%d: Log [%s]: %s", second, milli, id, msg)
	o.mu.Unlock()

	select {
	case o.Logs <- msg:
	default:
	}
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
