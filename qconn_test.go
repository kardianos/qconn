package qconn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestMain(m *testing.M) {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")
	os.Exit(m.Run())
}

// echoRequest is used for client-to-client echo tests.
type echoRequest struct {
	Message string `cbor:"message"`
}

func (echoRequest) Type() string { return "echo" }

// slowRequest is used for slow handler tests.
type slowRequest struct {
	Message string `cbor:"message"`
}

func (slowRequest) Type() string { return "slow" }

// printRequest is used for device routing tests.
type printRequest struct {
	Document string `cbor:"doc"`
}

func (printRequest) Type() string { return "print" }

// scanRequest is used for device routing tests.
type scanRequest struct{}

func (scanRequest) Type() string { return "scan" }

// mockClientRecord stores client status for testing.
type mockClientRecord struct {
	status             ClientStatus
	expiresAt          time.Time
	createdAt          time.Time
	updatedAt          time.Time
	hostname           string
	machineIP          string
	remoteIP           string
	devices            []DeviceInfo
	msgTypes           []string
	authorizedMsgTypes []string
}

// mockAuthManager is a simple in-memory auth manager for testing.
type mockAuthManager struct {
	mu              sync.Mutex
	caCert          *x509.Certificate
	caKey           *ecdsa.PrivateKey
	serverCert      *tls.Certificate
	provisionTokens map[string]bool
	authTokens      map[TA]bool
	clients         map[FP]*mockClientRecord

	// Provisioning support.
	provisionPool  *x509.CertPool                     // Pool of derived CAs for verifying provisioning clients.
	provisionCerts map[string]*mockProvisionCertEntry // SNI -> server cert entry.
}

type mockProvisionCertEntry struct {
	cert *tls.Certificate
	ca   tls.Certificate
}

func newMockAuthManager(t *testing.T) *mockAuthManager {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	return &mockAuthManager{
		caCert:          caCert,
		caKey:           caKey,
		provisionTokens: make(map[string]bool),
		authTokens:      make(map[TA]bool),
		clients:         make(map[FP]*mockClientRecord),
		provisionPool:   x509.NewCertPool(),
		provisionCerts:  make(map[string]*mockProvisionCertEntry),
	}
}

func (m *mockAuthManager) ServerCertificate(sni string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for provisioning SNI first.
	if strings.HasPrefix(sni, "provision-") {
		if entry, ok := m.provisionCerts[sni]; ok {
			return entry.cert, nil
		}
	}

	if m.serverCert != nil {
		return m.serverCert, nil
	}
	certPEM, keyPEM, err := m.createCert("localhost", true)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	m.serverCert = &cert
	return m.serverCert, nil
}

func (m *mockAuthManager) VerifyClientCertificate(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return ErrNoClientCert
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}

	// Check for provisioning certificate.
	if isProvisioningCert(leaf) {
		opts := x509.VerifyOptions{
			Roots:     m.provisionPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := leaf.Verify(opts); err != nil {
			return err
		}
		return nil
	}

	// For testing, verify against our CA.
	opts := x509.VerifyOptions{
		Roots:     m.RootCertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	_, err = leaf.Verify(opts)
	return err
}

func (m *mockAuthManager) RootCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	return pool
}

func (m *mockAuthManager) ValidAuthToken(token TA, fp FP) (bool, time.Time, error) {
	if !m.authTokens[token] {
		return false, time.Time{}, nil
	}
	return true, time.Now().Add(24 * time.Hour), nil
}

func (m *mockAuthManager) SetProvisionTokens(tokens []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.provisionTokens = make(map[string]bool)
	m.provisionPool = x509.NewCertPool()
	m.provisionCerts = make(map[string]*mockProvisionCertEntry)

	for _, t := range tokens {
		m.provisionTokens[t] = true

		// Create derived CA for this token.
		ca, err := GenerateDerivedCA(t)
		if err != nil {
			continue
		}
		leaf, err := x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			continue
		}
		m.provisionPool.AddCert(leaf)

		// Generate provisioning server cert.
		sni := ProvisioningServerName(t)
		serverCert, _, err := GenerateProvisioningServerCert(ca, sni)
		if err != nil {
			continue
		}
		m.provisionCerts[sni] = &mockProvisionCertEntry{
			cert: &serverCert,
			ca:   ca,
		}
	}
}

func (m *mockAuthManager) SetAuthTokens(tokens []TA) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authTokens = make(map[TA]bool)
	for _, t := range tokens {
		m.authTokens[t] = true
	}
}

func (m *mockAuthManager) GetClientStatus(fp FP) (ClientStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.clients[fp]; ok {
		if time.Now().After(rec.expiresAt) {
			return StatusUnknown, nil
		}
		return rec.status, nil
	}
	return StatusUnknown, nil
}

func (m *mockAuthManager) SetClientStatus(fp FP, status ClientStatus, expiresAt time.Time, authorizedMsgTypes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if rec, ok := m.clients[fp]; ok {
		rec.status = status
		rec.expiresAt = expiresAt
		rec.updatedAt = now
		if status == StatusRevoked {
			rec.authorizedMsgTypes = nil
		} else {
			rec.authorizedMsgTypes = authorizedMsgTypes
		}
	} else {
		var authTypes []string
		if status != StatusRevoked {
			authTypes = authorizedMsgTypes
		}
		m.clients[fp] = &mockClientRecord{
			status:             status,
			expiresAt:          expiresAt,
			createdAt:          now,
			updatedAt:          now,
			authorizedMsgTypes: authTypes,
		}
	}
	return nil
}

func (m *mockAuthManager) GetClientRecord(fp FP) (*ClientRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.clients[fp]
	if !ok {
		return nil, nil
	}
	if time.Now().After(rec.expiresAt) {
		return nil, nil
	}
	return &ClientRecord{
		Fingerprint:        fp,
		Hostname:           rec.hostname,
		Status:             rec.status,
		CreatedAt:          rec.createdAt,
		ExpiresAt:          rec.expiresAt,
		UpdatedAt:          rec.updatedAt,
		MachineIP:          rec.machineIP,
		RemoteIP:           rec.remoteIP,
		Devices:            rec.devices,
		MsgTypes:           rec.msgTypes,
		AuthorizedMsgTypes: rec.authorizedMsgTypes,
	}, nil
}

func (m *mockAuthManager) UpdateClientInfo(fp FP, info *ClientInfoUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.clients[fp]
	if !ok {
		return ErrNotConnected
	}
	if info.MachineIP != "" {
		rec.machineIP = info.MachineIP
	}
	if info.RemoteIP != "" {
		rec.remoteIP = info.RemoteIP
	}
	if info.Devices != nil {
		rec.devices = info.Devices
	}
	if info.MsgTypes != nil {
		rec.msgTypes = info.MsgTypes
	}
	rec.updatedAt = time.Now()
	return nil
}

func (m *mockAuthManager) SetClientRoles(fp FP, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.clients[fp]
	if !ok {
		return ErrNotConnected
	}
	_ = roles // Mock ignores roles.
	rec.updatedAt = time.Now()
	return nil
}

func (m *mockAuthManager) ListClientRecord(filter *ClientRecordFilter) ([]*ClientRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var records []*ClientRecord
	for fp, rec := range m.clients {
		// Skip expired records.
		if now.After(rec.expiresAt) {
			continue
		}
		// Apply filters.
		if filter != nil {
			if filter.FP != nil && fp != *filter.FP {
				continue
			}
			if filter.Status != nil && rec.status != *filter.Status {
				continue
			}
			// Roles filter not implemented in mock.
		}
		records = append(records, &ClientRecord{
			Fingerprint:        fp,
			Hostname:           rec.hostname,
			Status:             rec.status,
			ExpiresAt:          rec.expiresAt,
			UpdatedAt:          rec.updatedAt,
			AuthorizedMsgTypes: rec.authorizedMsgTypes,
		})
	}
	return records, nil
}

func (m *mockAuthManager) Allow(act Action, originator FP, target FP, msgType string, role string) (bool, error) {
	// Default: allow all actions.
	return true, nil
}

func (m *mockAuthManager) RootCertPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw}), nil
}

func (m *mockAuthManager) SignProvisioningCSR(csrPEM []byte, hostname string) ([]byte, error) {
	// Reject reserved hostnames.
	if strings.HasPrefix(hostname, ReservedHostnamePrefix) {
		return nil, ErrReservedHostname
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, ErrInvalidRequest
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	certPEM, err := m.signCSR(csr, hostname)
	if err != nil {
		return nil, err
	}

	// Create client record with authenticated status (matching real impl).
	block, _ = pem.Decode(certPEM)
	if block != nil {
		if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
			fp := FingerprintOf(leaf)
			now := time.Now()
			m.mu.Lock()
			m.clients[fp] = &mockClientRecord{
				status:    StatusAuthenticated,
				expiresAt: leaf.NotAfter,
				createdAt: now,
				updatedAt: now,
				hostname:  hostname,
			}
			m.mu.Unlock()
		}
	}

	return certPEM, nil
}

func (m *mockAuthManager) SignRenewalCSR(csrPEM []byte, hostname string) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, ErrInvalidRequest
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return m.signCSR(csr, hostname)
}

func (m *mockAuthManager) createCert(hostname string, isServer bool) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{hostname, "localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

func (m *mockAuthManager) signCSR(csr *x509.CertificateRequest, hostname string) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, csr.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// clientAuth creates a CredentialStore for a client with pre-generated credentials.
// It also pre-authorizes the client in the mock store.
func (m *mockAuthManager) clientAuth(hostname string) (*MemoryCredentialStore, error) {
	return m.clientAuthWithStatus(hostname, StatusAuthenticated)
}

// clientAuthPending creates a CredentialStore without pre-authenticating the client.
func (m *mockAuthManager) clientAuthPending(hostname string) (*MemoryCredentialStore, error) {
	return m.clientAuthWithStatus(hostname, StatusUnauthenticated)
}

// clientAuthWithStatus creates a CredentialStore with a specific initial status.
func (m *mockAuthManager) clientAuthWithStatus(hostname string, status ClientStatus) (*MemoryCredentialStore, error) {
	certPEM, keyPEM, err := m.createCert(hostname, false)
	if err != nil {
		return nil, err
	}

	// Parse cert to get fingerprint and set status.
	block, _ := pem.Decode(certPEM)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			fp := FingerprintOf(cert)
			m.mu.Lock()
			m.clients[fp] = &mockClientRecord{
				hostname:  hostname,
				status:    status,
				expiresAt: cert.NotAfter,
			}
			m.mu.Unlock()
		}
	}

	rootCAPEM, err := m.RootCertPEM()
	if err != nil {
		return nil, err
	}
	return NewMemoryCredentialStoreWithCreds(certPEM, keyPEM, rootCAPEM), nil
}

func TestServerClientBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)
	auth.SetProvisionTokens([]string{"test-token"})

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start server.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		if err := server.Serve(ctx, conn); err != nil {
			t.Error(err)
		}
	}()

	// Create client with a regular certificate.
	clientAuth, err := auth.clientAuth("test-client")
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ctx, ClientOpt{
		ServerAddr: conn.LocalAddr().String(),
		Auth:       clientAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	// Test admin/client/list request.
	var clients []*ClientRecord
	err = client.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err != nil {
		t.Fatalf("admin/client/list failed: %v", err)
	}

	// Should see ourselves in the list.
	if len(clients) == 0 {
		t.Error("expected at least one client in list")
	}
	t.Logf("Connected clients: %+v", clients)
}

func TestClientToClientRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start server.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		if err := server.Serve(ctx, conn); err != nil {
			t.Error(err)
		}
	}()

	serverAddr := conn.LocalAddr().String()

	// Create client A.
	authA, err := auth.clientAuth("client-a")
	if err != nil {
		t.Fatal(err)
	}
	clientA, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       authA,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientA.Close() }()

	// Create client B with a handler.
	authB, err := auth.clientAuth("client-b")
	if err != nil {
		t.Fatal(err)
	}

	echoHandler := func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
		_, err := w.Write(msg.Payload)
		return err
	}

	clientB, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       authB,
		Handler:    echoHandler,
	})
	if err != nil {
		t.Fatalf("client B connect failed: %v", err)
	}
	defer func() { _ = clientB.Close() }()

	// Verify client B is connected by having it list clients too.
	var clientsFromB []*ClientRecord
	if err := clientB.Request(ctx, System(), "", &AdminClientListRequest{}, &clientsFromB); err != nil {
		t.Fatalf("client B admin/client/list failed: %v", err)
	}
	t.Logf("Clients from B perspective: %+v", clientsFromB)

	// Get list of clients to see what's registered.
	var clients []*ClientRecord
	if err := clientA.Request(ctx, System(), "", &AdminClientListRequest{}, &clients); err != nil {
		t.Fatalf("admin/client/list failed: %v", err)
	}
	t.Logf("Connected clients: %+v", clients)

	// Client A sends request to client B.
	reqPayload := echoRequest{Message: "hello from A"}
	var respPayload echoRequest
	err = clientA.Request(ctx, ToMachine("client-b"), "", &reqPayload, &respPayload)
	if err != nil {
		t.Fatalf("request to client B failed: %v", err)
	}

	if respPayload.Message != reqPayload.Message {
		t.Errorf("expected %q, got %q", reqPayload.Message, respPayload.Message)
	}
}

func TestBoltAuthManagerFullProvisioning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create temp directory for bbolt database.
	tempDir, err := os.MkdirTemp("", "qconn-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Shared provisioning token - the only secret clients need to know.
	provisionToken := "test-provision-secret-token-12345"

	// Create BoltAuthManager with provisioning token.
	auth, _, err := NewBoltAuthManager(BoltAuthConfig{
		DBPath:          filepath.Join(tempDir, "auth.db"),
		ServerHostname:  "localhost",
		ProvisionTokens: []string{provisionToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	// Create and start server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Connect client 1 - will provision automatically.
	auth1 := NewMemoryCredentialStore(provisionToken, "client-alpha")
	var client1 *Client
	defer func() {
		if client1 != nil {
			_ = client1.Close()
		}
	}()

	client1, err = NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       auth1,
	})
	if err != nil {
		t.Fatalf("client1 failed: %v", err)
	}

	// Connect client 2 with a handler - will provision automatically.
	echoHandler := func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
		_, err := w.Write(msg.Payload)
		return err
	}

	auth2 := NewMemoryCredentialStore(provisionToken, "client-beta")
	var client2 *Client
	defer func() {
		if client2 != nil {
			_ = client2.Close()
		}
	}()

	client2, err = NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       auth2,
		Handler:    echoHandler,
	})
	if err != nil {
		t.Fatalf("client2 failed: %v", err)
	}

	// Verify clients are connected by issuing non-admin system requests.
	// (Admin messages require temp auth or RBAC permission.)
	if err := client1.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil); err != nil {
		t.Fatalf("client1 update-client-info failed: %v", err)
	}
	if err := client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil); err != nil {
		t.Fatalf("client2 update-client-info failed: %v", err)
	}

	// Verify both clients are stored (use auth manager directly since admin endpoint needs temp auth).
	storedClientsEarly, err := auth.ListClients()
	if err != nil {
		t.Fatalf("ListClients failed: %v", err)
	}
	if len(storedClientsEarly) != 2 {
		t.Errorf("expected 2 clients, got %d: %+v", len(storedClientsEarly), storedClientsEarly)
	}

	// Approve both clients so they can communicate.
	// (Provisioned clients start as unauthenticated and need admin approval.)
	for _, rec := range storedClientsEarly {
		if err := auth.SetClientStatus(rec.Fingerprint, StatusAuthenticated, rec.ExpiresAt, nil); err != nil {
			t.Fatalf("SetClientStatus failed: %v", err)
		}
	}

	// Reconnect clients to pick up the new status.
	client1.Close()
	client1 = nil
	client2.Close()
	client2 = nil

	// Wait for server to process disconnections and clean up.
	time.Sleep(100 * time.Millisecond)

	// Reconnect client 1.
	client1, err = NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       auth1,
	})
	if err != nil {
		t.Fatalf("client1 reconnect failed: %v", err)
	}

	// Reconnect client 2 with handler.
	client2, err = NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       auth2,
		Handler:    echoHandler,
	})
	if err != nil {
		t.Fatalf("client2 reconnect failed: %v", err)
	}

	// Verify both clients reconnected successfully by issuing system requests.
	if err := client1.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil); err != nil {
		t.Fatalf("reconnected client1 update-client-info failed: %v", err)
	}
	if err := client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil); err != nil {
		t.Fatalf("reconnected client2 update-client-info failed: %v", err)
	}
	t.Log("Both clients reconnected successfully")

	// Client 1 sends message to client 2.
	reqPayload := echoRequest{Message: "hello from alpha to beta"}
	var respPayload echoRequest

	if err := client1.Request(ctx, ToMachine("client-beta"), "", &reqPayload, &respPayload); err != nil {
		t.Fatalf("client1 -> client2 request failed: %v", err)
	}

	if respPayload.Message != reqPayload.Message {
		t.Errorf("expected %q, got %q", reqPayload.Message, respPayload.Message)
	}
}

func TestBoltAuthManagerDuplicateMachine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create temp directory for bbolt database.
	tempDir, err := os.MkdirTemp("", "qconn-duplicate-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	provisionToken := "test-provision-token"

	// Create BoltAuthManager with provisioning token.
	auth, _, err := NewBoltAuthManager(BoltAuthConfig{
		DBPath:          filepath.Join(tempDir, "auth.db"),
		ServerHostname:  "localhost",
		ProvisionTokens: []string{provisionToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	// Create and start server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Connect client 1 with hostname "same-machine".
	auth1 := NewMemoryCredentialStore(provisionToken, "same-machine")
	client1, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       auth1,
	})
	if err != nil {
		t.Fatalf("client1 failed to connect: %v", err)
	}
	defer func() { _ = client1.Close() }()

	// Verify client 1 is connected.
	if err := client1.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil); err != nil {
		t.Fatalf("client1 update-client-info failed: %v", err)
	}

	// Connect client 2 with the same hostname "same-machine".
	// The server should replace client 1's connection with client 2
	// (to support reconnection after provisioning with new cert).
	auth2 := NewMemoryCredentialStore(provisionToken, "same-machine")
	client2, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       auth2,
	})
	if err != nil {
		t.Fatalf("client2 failed to connect: %v", err)
	}
	defer func() { _ = client2.Close() }()

	// Client 2 should work (it replaced client 1).
	if err := client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil); err != nil {
		t.Fatalf("client2 request failed: %v", err)
	}

	// Client 1's connection should have been closed by the server.
	// A request should fail.
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shortCancel()

	err = client1.Request(shortCtx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.3"}, nil)
	if err == nil {
		t.Fatal("expected client1 request to fail after being replaced, but it succeeded")
	}
	t.Logf("client1 request failed as expected after replacement: %v", err)
}

func TestSlowHandler(t *testing.T) {
	resetFakeTime() // Ensure no fake time pollution from previous tests.

	// requestTimeout is 200ms.
	// To test ack properly, we need a scenario where:
	// - Without ack: total time > 200ms → timeout
	// - With ack: ack extends deadline, total time still works
	//
	// Handler does: preAckDelay, [optional ack], postAckDelay
	// With ack at preAckDelay, deadline becomes preAckDelay + 200ms
	// Handler finishes at preAckDelay + postAckDelay
	// Success if: preAckDelay + postAckDelay < preAckDelay + 200ms
	// i.e., postAckDelay < 200ms

	tests := []struct {
		name          string
		useAck        bool
		preAckDelay   time.Duration // delay before calling ack
		postAckDelay  time.Duration // delay after calling ack
		expectTimeout bool
	}{
		{
			name:          "WithoutAckTimesOut",
			useAck:        false,
			preAckDelay:   0,
			postAckDelay:  300 * time.Millisecond, // 300ms > 200ms timeout
			expectTimeout: true,
		},
		{
			name:          "WithAckSucceeds",
			useAck:        true,
			preAckDelay:   100 * time.Millisecond, // do work before ack
			postAckDelay:  150 * time.Millisecond, // 150ms < 200ms extended deadline
			expectTimeout: false,                  // total 250ms would timeout without ack, but ack saves it
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			auth := newMockAuthManager(t)

			server, err := NewServer(ServerOpt{
				Auth:           auth,
				Clients:        auth,
				RequestTimeout: 200 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}

			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()

			go func() {
				if err := server.Serve(ctx, conn); err != nil {
					t.Error(err)
				}
			}()

			serverAddr := conn.LocalAddr().String()

			authA, err := auth.clientAuth("client-a")
			if err != nil {
				t.Fatal(err)
			}
			clientA, err := NewClient(ctx, ClientOpt{
				ServerAddr: serverAddr,
				Auth:       authA,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = clientA.Close() }()

			authB, err := auth.clientAuth("client-b")
			if err != nil {
				t.Fatal(err)
			}

			useAck := tc.useAck
			preAckDelay := tc.preAckDelay
			postAckDelay := tc.postAckDelay
			handler := func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
				time.Sleep(preAckDelay)
				if useAck {
					if err := ack(ctx); err != nil {
						return err
					}
				}
				time.Sleep(postAckDelay)
				_, err := w.Write(msg.Payload)
				return err
			}

			clientB, err := NewClient(ctx, ClientOpt{
				ServerAddr: serverAddr,
				Auth:       authB,
				Handler:    handler,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = clientB.Close() }()

			var clients []*ClientRecord
			if err := clientB.Request(ctx, System(), "", &AdminClientListRequest{}, &clients); err != nil {
				t.Fatal(err)
			}

			reqPayload := slowRequest{Message: "hello"}
			var respPayload slowRequest

			err = clientA.Request(ctx, ToMachine("client-b"), "", &reqPayload, &respPayload)

			if tc.expectTimeout {
				if err == nil {
					t.Fatal("expected timeout error, got nil")
				}
				if reqErr, ok := err.(*RequestError); ok {
					if reqErr.Message != ErrTimeout.Error() {
						t.Errorf("expected timeout error, got: %v", err)
					}
				} else {
					t.Errorf("expected RequestError, got: %T %v", err, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if respPayload.Message != reqPayload.Message {
					t.Errorf("expected %q, got %q", reqPayload.Message, respPayload.Message)
				}
			}
		})
	}
}

func TestSelfAuthorization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)
	validSecretAuth := TA{1, 2, 3}
	invalidSecretAuth := TA{4, 5, 6}
	auth.SetAuthTokens([]TA{validSecretAuth})

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Create client (will be in pending-auth state).
	clientAuth, err := auth.clientAuthPending("self-auth-client")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	// Try to list clients - should fail because we're in pending-auth state.
	var clients []*ClientRecord
	err = client.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err == nil {
		t.Fatal("expected error for pending-auth client calling admin/client/list")
	}

	// Self-authorize with invalid token - should fail.
	err = client.Request(ctx, System(), "", &SelfAuthorizeRequest{Token: invalidSecretAuth}, nil)
	if err == nil {
		t.Fatal("expected error for invalid auth token")
	}

	// Self-authorize with valid token - should succeed.
	err = client.Request(ctx, System(), "", &SelfAuthorizeRequest{Token: validSecretAuth}, nil)
	if err != nil {
		t.Fatalf("self-authorize failed: %v", err)
	}

	// Now list clients should work.
	err = client.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err != nil {
		t.Fatalf("admin/client/list failed after self-authorize: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(clients))
	}
}

func TestAuthorizeClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Echo handler for admin client.
	echoHandler := func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
		_, err := w.Write(msg.Payload)
		return err
	}

	// Create admin client (will be authorized) with a handler.
	adminAuth, err := auth.clientAuth("admin-client")
	if err != nil {
		t.Fatal(err)
	}
	adminClient, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       adminAuth,
		Handler:    echoHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adminClient.Close() }()

	// Verify admin is connected.
	var clients []*ClientRecord
	if err := adminClient.Request(ctx, System(), "", &AdminClientListRequest{}, &clients); err != nil {
		t.Fatalf("admin admin/client/list failed: %v", err)
	}

	// Create pending client.
	pendingAuth, err := auth.clientAuthPending("pending-client")
	if err != nil {
		t.Fatal(err)
	}
	pendingClient, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       pendingAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pendingClient.Close() }()

	// Get pending client's fingerprint.
	block, _ := pem.Decode(pendingAuth.CertPEM())
	pendingCert, _ := x509.ParseCertificate(block.Bytes)
	pendingFP := FingerprintOf(pendingCert)

	// Pending client can't list clients (system endpoint).
	err = pendingClient.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err == nil {
		t.Fatal("expected error for pending client calling admin/client/list")
	}

	// Pending client can't send messages to other clients either.
	reqPayload := echoRequest{Message: "hello from pending"}
	var respPayload echoRequest
	err = pendingClient.Request(ctx, ToMachine("admin-client"), "", &reqPayload, &respPayload)
	if err == nil {
		t.Fatal("expected error for pending client sending to another client")
	}
	t.Logf("Pending client routing error (expected): %v", err)

	// Admin authorizes the pending client by FP with roles (roles required for auth).
	err = adminClient.Request(ctx, System(), "", &AuthorizeClientRequest{FP: pendingFP, Roles: []string{"client"}}, nil)
	if err != nil {
		t.Fatalf("admin/client/auth failed: %v", err)
	}

	// Now pending client can list clients.
	err = pendingClient.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err != nil {
		t.Fatalf("admin/client/list failed after admin/client/auth: %v", err)
	}
	if len(clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(clients))
	}

	// Now pending client can also send messages to other clients.
	err = pendingClient.Request(ctx, ToMachine("admin-client"), "", &reqPayload, &respPayload)
	if err != nil {
		t.Fatalf("request to admin failed after authorization: %v", err)
	}
	if respPayload.Message != reqPayload.Message {
		t.Errorf("expected %q, got %q", reqPayload.Message, respPayload.Message)
	}
}

func TestBoltAuthManagerCleanup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "qconn-cleanup-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	auth, _, err := NewBoltAuthManager(BoltAuthConfig{
		DBPath:          filepath.Join(tempDir, "auth.db"),
		ServerHostname:  "localhost",
		ProvisionTokens: []string{"test-provision-secret-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	// Add some client records with different expiration times.
	now := time.Now()
	expiredFP := FP{1, 2, 3}
	validFP := FP{4, 5, 6}

	// Add expired record.
	if err := auth.SetClientStatus(expiredFP, StatusAuthenticated, now.Add(-time.Hour), nil); err != nil {
		t.Fatal(err)
	}

	// Add valid record.
	if err := auth.SetClientStatus(validFP, StatusAuthenticated, now.Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}

	// Verify both records exist.
	clients, err := auth.ListClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(clients))
	}

	// Run cleanup.
	removed, err := auth.CleanupExpired()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	// Verify only valid record remains.
	clients, err = auth.ListClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 {
		t.Errorf("expected 1 client after cleanup, got %d", len(clients))
	}

	// Check the remaining client is the valid one.
	if len(clients) > 0 && clients[0].Fingerprint != validFP {
		t.Errorf("expected valid FP to remain, got %v", clients[0].Fingerprint)
	}
}

func TestUpdateClientInfo(t *testing.T) {
	resetFakeTime() // Ensure no fake time pollution from previous tests.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Create client.
	clientAuth, err := auth.clientAuth("test-machine")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	// Verify client is connected.
	var clients []*ClientRecord
	if err := client.Request(ctx, System(), "", &AdminClientListRequest{}, &clients); err != nil {
		t.Fatalf("admin/client/list failed: %v", err)
	}

	// Get client's fingerprint.
	block, _ := pem.Decode(clientAuth.CertPEM())
	clientCert, _ := x509.ParseCertificate(block.Bytes)
	clientFP := FingerprintOf(clientCert)

	// Update client info.
	updateInfo := ClientInfoUpdate{
		MachineIP: "192.168.1.100",
		Devices: []DeviceInfo{
			{Name: "printer1", Type: "printer"},
			{Name: "scanner1", Type: "scanner"},
		},
	}
	if err := client.Request(ctx, System(), "", &updateInfo, nil); err != nil {
		t.Fatalf("update-client-info failed: %v", err)
	}

	// Verify the info was stored.
	rec, err := auth.GetClientRecord(clientFP)
	if err != nil {
		t.Fatalf("GetClientRecord failed: %v", err)
	}
	if rec == nil {
		t.Fatal("expected client record, got nil")
	}

	if rec.MachineIP != "192.168.1.100" {
		t.Errorf("expected MachineIP 192.168.1.100, got %s", rec.MachineIP)
	}
	if rec.RemoteIP == "" {
		t.Error("expected RemoteIP to be set by server")
	}
	if len(rec.Devices) != 2 {
		t.Errorf("expected 2 devices, got %d", len(rec.Devices))
	}

	// Verify devices are now routable by type.
	var clientsWithDevices []*ClientRecord
	if err := client.Request(ctx, System(), "", &AdminClientListRequest{}, &clientsWithDevices); err != nil {
		t.Fatalf("admin/client/list failed: %v", err)
	}

	// Find our client in the list.
	var found bool
	for _, c := range clientsWithDevices {
		if c.Hostname == "test-machine" {
			found = true
			if len(c.Devices) != 2 {
				t.Errorf("expected 2 devices in list, got %d", len(c.Devices))
			}
		}
	}
	if !found {
		t.Error("client not found in list")
	}

	t.Logf("Client record: MachineIP=%s, RemoteIP=%s, Devices=%v",
		rec.MachineIP, rec.RemoteIP, rec.Devices)
}

func TestDeviceTypeRouting(t *testing.T) {
	resetFakeTime() // Ensure no fake time pollution from previous tests.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Create sender client.
	senderAuth, err := auth.clientAuth("sender")
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       senderAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()

	// Create printer client with handler.
	printerAuth, err := auth.clientAuth("printer-machine")
	if err != nil {
		t.Fatal(err)
	}

	printHandler := func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
		resp := struct {
			Status string `cbor:"status"`
		}{Status: "printed"}
		return cbor.NewEncoder(w).Encode(resp)
	}

	printer, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       printerAuth,
		Handler:    printHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = printer.Close() }()

	// Register printer with device type.
	err = printer.Request(ctx, System(), "", &ClientInfoUpdate{
		Devices: []DeviceInfo{
			{Name: "hp-printer-1", Type: "printer"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("update-client-info failed: %v", err)
	}

	// Test 1: Route by device type.
	type printResp struct {
		Status string `cbor:"status"`
	}
	var resp printResp
	err = sender.Request(ctx, ToType("printer"), "", &printRequest{Document: "test.pdf"}, &resp)
	if err != nil {
		t.Fatalf("ToType(printer) request failed: %v", err)
	}
	if resp.Status != "printed" {
		t.Errorf("expected status 'printed', got %q", resp.Status)
	}
	t.Log("Device type routing: OK")

	// Test 2: Route to non-existent type.
	err = sender.Request(ctx, ToType("scanner"), "", &scanRequest{}, nil)
	if err == nil {
		t.Fatal("expected error for non-existent device type")
	}
	if reqErr, ok := err.(*RequestError); ok {
		if reqErr.Message != ErrTypeNotFound.Error() {
			t.Errorf("expected %q error, got %q", ErrTypeNotFound, reqErr.Message)
		}
	} else {
		t.Errorf("expected RequestError, got %T: %v", err, err)
	}
	t.Log("Non-existent device type error: OK")

	// Test 3: Route to specific device on machine.
	err = sender.Request(ctx, ToDevice("printer-machine", "hp-printer-1"), "", &printRequest{Document: "another.pdf"}, &resp)
	if err != nil {
		t.Fatalf("ToDevice request failed: %v", err)
	}
	t.Log("Specific device routing: OK")

	// Test 4: Route to non-existent device on machine.
	err = sender.Request(ctx, ToDevice("printer-machine", "nonexistent-device"), "", &printRequest{}, nil)
	if err == nil {
		t.Fatal("expected error for non-existent device")
	}
	if reqErr, ok := err.(*RequestError); ok {
		if reqErr.Message != ErrDeviceNotFound.Error() {
			t.Errorf("expected %q error, got %q", ErrDeviceNotFound, reqErr.Message)
		}
	} else {
		t.Errorf("expected RequestError, got %T: %v", err, err)
	}
	t.Log("Non-existent device error: OK")
}

func TestRevokedClientRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Create client credentials.
	certPEM, keyPEM, err := auth.createCert("revoked-client", false)
	if err != nil {
		t.Fatal(err)
	}
	rootCAPEM, _ := auth.RootCertPEM()

	// Parse cert to get FP and mark as revoked.
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	fp := FingerprintOf(cert)

	auth.mu.Lock()
	auth.clients[fp] = &mockClientRecord{
		status:    StatusRevoked,
		expiresAt: time.Now().Add(time.Hour),
	}
	auth.mu.Unlock()

	// Try to connect - should fail during connection handling.
	// Use a short timeout context for the connect attempt.
	connectCtx, connectCancel := context.WithTimeout(ctx, 2*time.Second)
	defer connectCancel()

	creds := NewMemoryCredentialStoreWithCreds(certPEM, keyPEM, rootCAPEM)
	client, err := NewClient(connectCtx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       creds,
	})

	// Connection may succeed at TLS level but fail at protocol level.
	// The server closes the connection with error code 1 "certificate revoked".
	if client != nil {
		// Try to make a request with short timeout - it should fail.
		reqCtx, reqCancel := context.WithTimeout(ctx, 1*time.Second)
		defer reqCancel()

		var clients []*ClientRecord
		err = client.Request(reqCtx, System(), "", &AdminClientListRequest{}, &clients)
		if err == nil {
			t.Error("expected error for revoked client request")
		}
		_ = client.Close()
	}
	t.Log("Revoked client rejected: OK")
}

func TestMessageSizeLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)
	authToken := TA{2, 1, 3}
	auth.SetAuthTokens([]TA{authToken})

	// Server with small limits for testing.
	server, err := NewServer(ServerOpt{
		Auth:                      auth,
		Clients:                   auth,
		UnauthenticatedMaxMsgSize: 1024,      // 1 KB for unauthenticated
		AuthenticatedMaxMsgSize:   10 * 1024, // 10 KB for authenticated
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Test 1: Unauthenticated client - small message should work.
	t.Run("UnauthenticatedSmallMessage", func(t *testing.T) {
		pendingAuth, err := auth.clientAuthPending("pending-small")
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       pendingAuth,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()

		smallPayload := ClientInfoUpdate{MachineIP: "10.0.0.1"}
		err = client.Request(ctx, System(), "", &smallPayload, nil)
		if err != nil {
			t.Fatalf("small message should work: %v", err)
		}
	})

	// Test 2: Unauthenticated client - large message should cause connection close.
	t.Run("UnauthenticatedLargeMessage", func(t *testing.T) {
		pendingAuth, err := auth.clientAuthPending("pending-large")
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       pendingAuth,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()

		// First send a small message to ensure connection works.
		smallPayload := ClientInfoUpdate{MachineIP: "10.0.0.1"}
		err = client.Request(ctx, System(), "", &smallPayload, nil)
		if err != nil {
			t.Fatalf("small message should work first: %v", err)
		}

		// Now send a large message. Server will close connection.
		largeIP := string(make([]byte, 2000))
		largePayload := ClientInfoUpdate{MachineIP: largeIP}

		reqCtx, reqCancel := context.WithTimeout(ctx, 2*time.Second)
		defer reqCancel()

		err = client.Request(reqCtx, System(), "", &largePayload, nil)
		if err == nil {
			t.Fatal("large message should fail")
		}
		// Connection closed or timeout is expected.
		t.Logf("Large message rejected (expected): %v", err)
	})

	// Test 3: Authenticated client - medium message should work.
	t.Run("AuthenticatedMediumMessage", func(t *testing.T) {
		authCreds, err := auth.clientAuth("auth-medium")
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       authCreds,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()

		mediumIP := string(make([]byte, 5000)) // 5KB
		mediumPayload := ClientInfoUpdate{MachineIP: mediumIP}
		err = client.Request(ctx, System(), "", &mediumPayload, nil)
		if err != nil {
			t.Fatalf("medium message should work: %v", err)
		}
	})

	// Test 4: Authenticated client - very large message should fail.
	t.Run("AuthenticatedVeryLargeMessage", func(t *testing.T) {
		authCreds, err := auth.clientAuth("auth-large")
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       authCreds,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()

		// First a small message to confirm connection works.
		smallPayload := ClientInfoUpdate{MachineIP: "10.0.0.1"}
		err = client.Request(ctx, System(), "", &smallPayload, nil)
		if err != nil {
			t.Fatalf("small message should work first: %v", err)
		}

		// Now very large message.
		veryLargeIP := string(make([]byte, 15000)) // 15KB
		veryLargePayload := ClientInfoUpdate{MachineIP: veryLargeIP}

		reqCtx, reqCancel := context.WithTimeout(ctx, 2*time.Second)
		defer reqCancel()

		err = client.Request(reqCtx, System(), "", &veryLargePayload, nil)
		if err == nil {
			t.Fatal("very large message should fail")
		}
		t.Logf("Very large message rejected (expected): %v", err)
	})

	// Test 5: After self-authorize, limit should increase.
	t.Run("LimitIncreasesAfterSelfAuth", func(t *testing.T) {
		pendingAuth, err := auth.clientAuthPending("upgrade-client")
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       pendingAuth,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()

		// Self-authorize first (small message).
		err = client.Request(ctx, System(), "", &SelfAuthorizeRequest{Token: authToken}, nil)
		if err != nil {
			t.Fatalf("self-authorize failed: %v", err)
		}

		// Now medium message should work (limit increased).
		mediumIP := string(make([]byte, 5000)) // 5KB
		mediumPayload := ClientInfoUpdate{MachineIP: mediumIP}
		err = client.Request(ctx, System(), "", &mediumPayload, nil)
		if err != nil {
			t.Fatalf("medium message after self-authorize should work: %v", err)
		}
	})
}

// mockResolver is a resolver that tracks calls for testing.
type mockResolver struct {
	mu        sync.Mutex
	addrs     map[string]string
	callCount int
}

func (r *mockResolver) Resolve(ctx context.Context, hostname string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callCount++
	addr, ok := r.addrs[hostname]
	if !ok {
		return "", errors.New("hostname not found")
	}
	return addr, nil
}

func (r *mockResolver) SetAddr(hostname, addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs[hostname] = addr
}

func (r *mockResolver) CallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.callCount
}

func TestDNSResolverChanges(t *testing.T) {
	resetFakeTime() // Ensure no fake time pollution from previous tests.

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Single auth manager/server for this test.
	auth := newMockAuthManager(t)
	auth.SetProvisionTokens([]string{"provision-token"})

	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	go func() { _ = server.Serve(ctx, conn) }()
	serverAddr := conn.LocalAddr().String()

	// Test 1: Resolver is called during provisioning.
	t.Run("ResolverCalledDuringProvisioning", func(t *testing.T) {
		resolver := &mockResolver{
			addrs: map[string]string{
				"myserver.local": serverAddr,
			},
		}

		clientCreds := NewMemoryCredentialStore("provision-token", "resolver-client-1")
		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: "myserver.local",
			Auth:       clientCreds,
			Resolver:   resolver,
		})
		if err != nil {
			t.Fatalf("connect failed: %v", err)
		}
		defer func() { _ = client.Close() }()

		// Provisioning involves: initial connect + reconnect after provisioning.
		// So resolver should be called at least twice.
		if resolver.CallCount() < 2 {
			t.Errorf("expected resolver called at least 2 times for provisioning, got %d", resolver.CallCount())
		}
		t.Logf("Resolver called %d times during provisioning", resolver.CallCount())

		// Verify connected.
		err = client.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}

		// Verify provisioned.
		if clientCreds.NeedsProvisioning() {
			t.Error("client should not need provisioning after connect")
		}
	})

	// Test 2: Resolver is called on reconnect with existing creds.
	t.Run("ResolverCalledOnReconnect", func(t *testing.T) {
		// Create client with existing credentials.
		existingCreds, err := auth.clientAuth("resolver-client-2")
		if err != nil {
			t.Fatal(err)
		}

		resolver := &mockResolver{
			addrs: map[string]string{
				"myserver.local": serverAddr,
			},
		}

		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: "myserver.local",
			Auth:       existingCreds,
			Resolver:   resolver,
		})
		if err != nil {
			t.Fatalf("connect failed: %v", err)
		}
		defer func() { _ = client.Close() }()

		// For non-provisioning client, resolver called once.
		if resolver.CallCount() != 1 {
			t.Errorf("expected resolver called 1 time for reconnect, got %d", resolver.CallCount())
		}
		t.Logf("Resolver called %d times on reconnect", resolver.CallCount())

		// Verify connected.
		err = client.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
	})

	// Test 3: Resolver address changes between disconnect and reconnect.
	t.Run("ResolverAddressChanges", func(t *testing.T) {
		// Start a second server.
		auth2 := newMockAuthManager(t)
		// Use same CA so certs work on both servers.
		auth2.caCert = auth.caCert
		auth2.caKey = auth.caKey

		server2, err := NewServer(ServerOpt{
			Auth:    auth2,
			Clients: auth2,
		})
		if err != nil {
			t.Fatal(err)
		}
		conn2, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn2.Close() }()
		go func() { _ = server2.Serve(ctx, conn2) }()
		server2Addr := conn2.LocalAddr().String()

		// Create creds that work on both servers (since they share CA).
		sharedCreds, err := auth.clientAuth("shared-client")
		if err != nil {
			t.Fatal(err)
		}

		// Also register the client on auth2 so server2 recognizes it.
		// In production, both servers would share a client database.
		fp := sharedCreds.Fingerprint()
		auth2.SetClientStatus(fp, StatusAuthenticated, time.Now().Add(time.Hour), nil)

		resolver := &mockResolver{
			addrs: map[string]string{
				"myserver.local": serverAddr, // Initially points to server 1.
			},
		}

		// Connect to server 1.
		client1, err := NewClient(ctx, ClientOpt{
			ServerAddr: "myserver.local",
			Auth:       sharedCreds,
			Resolver:   resolver,
		})
		if err != nil {
			t.Fatalf("first connect failed: %v", err)
		}

		// Verify connected to server 1.
		err = client1.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil)
		if err != nil {
			t.Fatalf("request to server 1 failed: %v", err)
		}
		t.Log("Connected to server 1")
		_ = client1.Close()

		// Change resolver to point to server 2.
		resolver.SetAddr("myserver.local", server2Addr)
		t.Logf("DNS changed to server 2: %s", server2Addr)

		// Reconnect - should go to server 2.
		client2, err := NewClient(ctx, ClientOpt{
			ServerAddr: "myserver.local",
			Auth:       sharedCreds,
			Resolver:   resolver,
		})
		if err != nil {
			t.Fatalf("reconnect failed: %v", err)
		}
		defer func() { _ = client2.Close() }()

		// Verify connected to server 2.
		err = client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil)
		if err != nil {
			t.Fatalf("request to server 2 failed: %v", err)
		}
		t.Log("Connected to server 2 after DNS change")
	})
}

// TestServerForgetsClientReProvisions tests that when a server "forgets" a client
// (e.g., server reset, database cleared), the client automatically detects this
// via StatusUnknown and re-provisions with a new certificate.
func TestServerForgetsClientReProvisions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)
	provisionToken := "test-provision-token"
	auth.SetProvisionTokens([]string{provisionToken})

	// Create and start server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Create client with provision token - will provision automatically.
	clientCreds := NewMemoryCredentialStore(provisionToken, "forgetful-client")
	client, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("initial connection failed: %v", err)
	}

	// Verify client provisioned successfully.
	if clientCreds.NeedsProvisioning() {
		t.Fatal("client should not need provisioning after initial connection")
	}

	// Get the original fingerprint.
	originalFP := clientCreds.Fingerprint()
	t.Logf("Original fingerprint: %s", originalFP)

	// Verify client can make requests.
	if err := client.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil); err != nil {
		t.Fatalf("initial request failed: %v", err)
	}

	// Close client connection.
	if err := client.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Simulate server "forgetting" the client by deleting from auth manager.
	auth.mu.Lock()
	delete(auth.clients, originalFP)
	t.Logf("Deleted client record for FP: %s (simulating server forget)", originalFP)
	auth.mu.Unlock()

	// Wait for server to clean up.
	time.Sleep(100 * time.Millisecond)

	// Reconnect with the SAME credential store (still has old credentials).
	// The client should detect StatusUnknown from queryStatus and auto-re-provision.
	client2, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("reconnect failed: %v", err)
	}
	defer func() { _ = client2.Close() }()

	// Verify client re-provisioned with a NEW fingerprint.
	newFP := clientCreds.Fingerprint()
	t.Logf("New fingerprint after re-provision: %s", newFP)

	if newFP == originalFP {
		t.Errorf("expected new fingerprint after re-provisioning, got same: %s", newFP)
	}

	// Verify client can make requests with new credentials.
	if err := client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil); err != nil {
		t.Fatalf("request after re-provision failed: %v", err)
	}

	t.Log("Client successfully auto-re-provisioned after server forgot it")
}

// TestServerRevokesClientReProvisions tests that when a server revokes a client,
// the client automatically detects this via StatusRevoked and re-provisions
// with a new certificate using the same provision token.
func TestServerRevokesClientReProvisions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)
	provisionToken := "test-provision-token"
	auth.SetProvisionTokens([]string{provisionToken})

	// Create and start server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Create client with provision token - will provision automatically.
	clientCreds := NewMemoryCredentialStore(provisionToken, "revokable-client")
	client, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("initial connection failed: %v", err)
	}

	// Verify client provisioned successfully.
	if clientCreds.NeedsProvisioning() {
		t.Fatal("client should not need provisioning after initial connection")
	}

	// Get the original fingerprint.
	originalFP := clientCreds.Fingerprint()
	t.Logf("Original fingerprint: %s", originalFP)

	// Verify client can make requests.
	if err := client.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil); err != nil {
		t.Fatalf("initial request failed: %v", err)
	}

	// Close client connection.
	if err := client.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Revoke the client.
	auth.mu.Lock()
	if rec, ok := auth.clients[originalFP]; ok {
		rec.status = StatusRevoked
		t.Logf("Revoked client with FP: %s", originalFP)
	} else {
		auth.mu.Unlock()
		t.Fatal("client record not found for revocation")
	}
	auth.mu.Unlock()

	// Wait for server to clean up.
	time.Sleep(100 * time.Millisecond)

	// Reconnect with the SAME credential store (still has old credentials).
	// The client should detect the server rejection (certificate revoked) and auto-re-provision.
	client2, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("reconnect failed: %v", err)
	}
	defer func() { _ = client2.Close() }()

	// Verify client re-provisioned with a NEW fingerprint.
	newFP := clientCreds.Fingerprint()
	t.Logf("New fingerprint after re-provision: %s", newFP)

	if newFP == originalFP {
		t.Errorf("expected new fingerprint after re-provisioning, got same: %s", newFP)
	}

	// Verify client can make requests with new credentials.
	if err := client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil); err != nil {
		t.Fatalf("request after re-provision failed: %v", err)
	}

	t.Log("Client successfully auto-re-provisioned after being revoked")
}

// TestServerRestartLongRunningClient tests that a long-running client
// properly detects when the server restarts and reconnects.
// This is the actual failure scenario: time-provider stays "running" but
// the server shows it as offline after restart.
func TestServerRestartLongRunningClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)
	provisionToken := "test-provision-token"
	auth.SetProvisionTokens([]string{provisionToken})

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := conn.LocalAddr().String()
	t.Logf("Server address: %s", serverAddr)

	serverCtx, serverCancel := context.WithCancel(ctx)
	serverDone := make(chan struct{})
	go func() {
		_ = server.Serve(serverCtx, conn)
		close(serverDone)
	}()

	// Create a long-running "provider" client that stays connected with auto-reconnect.
	providerCreds := NewMemoryCredentialStore(provisionToken, "long-running-provider")

	// Track reconnection.
	reconnected := make(chan struct{}, 1)

	provider, err := NewClient(ctx, ClientOpt{
		ServerAddr:     serverAddr,
		Auth:           providerCreds,
		MaxIdleTimeout: 1 * time.Second, // Short idle timeout to detect server death quickly
		OnReconnect: func(ctx context.Context, c *Client) error {
			// Re-register devices after reconnection.
			err := c.Request(ctx, System(), "", &ClientInfoUpdate{
				MachineIP: "10.0.0.1",
				Devices:   []DeviceInfo{{Name: "test-service", Type: "provider"}},
			}, nil)
			if err != nil {
				return err
			}
			select {
			case reconnected <- struct{}{}:
			default:
			}
			return nil
		},
		Handler: func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
			// Echo handler
			_, err := w.Write(msg.Payload)
			return err
		},
	})
	if err != nil {
		t.Fatalf("provider connection failed: %v", err)
	}

	providerFP := providerCreds.Fingerprint()
	t.Logf("Provider fingerprint: %s", providerFP)

	// Register provider's devices.
	err = provider.Request(ctx, System(), "", &ClientInfoUpdate{
		MachineIP: "10.0.0.1",
		Devices:   []DeviceInfo{{Name: "test-service", Type: "provider"}},
	}, nil)
	if err != nil {
		t.Fatalf("provider update info failed: %v", err)
	}

	// Approve the provider so it's authenticated.
	err = auth.SetClientStatus(providerFP, StatusAuthenticated, time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("approve provider failed: %v", err)
	}

	// Wait for provider to be in connected state.
	if err := provider.WaitForConnected(ctx); err != nil {
		t.Fatalf("provider wait for connected: %v", err)
	}
	t.Log("Provider is connected and authenticated")

	// Verify provider is listed and online.
	var clients []*ClientRecord
	err = provider.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err != nil {
		t.Fatalf("list clients failed: %v", err)
	}
	var providerOnline bool
	for _, c := range clients {
		if c.Fingerprint == providerFP {
			t.Logf("Provider status before restart: %s, online: %v", c.Status, c.Online)
			providerOnline = c.Online
		}
	}
	if !providerOnline {
		t.Fatal("provider should be online before server restart")
	}

	// Stop the server (simulate restart).
	t.Log("Stopping server...")
	serverCancel()
	_ = conn.Close()
	<-serverDone
	t.Log("Server stopped")

	// The provider client is still "running" - it hasn't errored yet.
	// In the real scenario, provider.Close() is NOT called.

	// Give the client time to potentially detect the disconnection.
	time.Sleep(100 * time.Millisecond)

	// Restart server on the same address.
	conn2, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to restart server: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	server2, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	serverCtx2, serverCancel2 := context.WithCancel(ctx)
	defer serverCancel2()
	go func() {
		_ = server2.Serve(serverCtx2, conn2)
	}()

	time.Sleep(100 * time.Millisecond)
	t.Log("Server restarted")

	// Create a new "consumer" client to check status.
	consumerCreds := NewMemoryCredentialStore(provisionToken, "consumer")
	consumer, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       consumerCreds,
	})
	if err != nil {
		t.Fatalf("consumer connection failed: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	consumerFP := consumerCreds.Fingerprint()
	err = auth.SetClientStatus(consumerFP, StatusAuthenticated, time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("approve consumer failed: %v", err)
	}

	// List clients from consumer's perspective.
	err = consumer.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err != nil {
		t.Fatalf("consumer list clients failed: %v", err)
	}

	// Check if provider shows as online (it likely won't be yet - reconnecting).
	var providerFoundOnline bool
	for _, c := range clients {
		t.Logf("Client after restart: %s (%s) online=%v status=%s",
			c.Hostname, c.Fingerprint, c.Online, c.Status)
		if c.Fingerprint == providerFP && c.Online {
			providerFoundOnline = true
		}
	}
	t.Logf("Provider online immediately after restart: %v (expected: false)", providerFoundOnline)

	// Initially, the provider may not be online yet (reconnecting).
	// Wait for it to reconnect.
	t.Log("Waiting for provider to reconnect...")
	select {
	case <-reconnected:
		t.Log("Provider reconnected successfully!")
	case <-time.After(5 * time.Second):
		t.Log("Timeout waiting for provider to reconnect")
	}

	// Give a moment for server to process the reconnection.
	time.Sleep(200 * time.Millisecond)

	// List clients again to verify provider is online.
	err = consumer.Request(ctx, System(), "", &AdminClientListRequest{}, &clients)
	if err != nil {
		t.Fatalf("consumer list clients (second attempt) failed: %v", err)
	}

	providerFoundOnline = false
	for _, c := range clients {
		t.Logf("Client after reconnect: %s (%s) online=%v status=%s",
			c.Hostname, c.Fingerprint, c.Online, c.Status)
		if c.Fingerprint == providerFP && c.Online {
			providerFoundOnline = true
		}
	}

	if !providerFoundOnline {
		t.Error("Provider should be online after auto-reconnect")
	}

	// Try to send a message to the provider by device type.
	reqPayload := echoRequest{Message: "hello"}
	var respPayload echoRequest
	err = consumer.Request(ctx, ToType("provider"), "", &reqPayload, &respPayload)
	if err != nil {
		t.Errorf("Request to provider failed after reconnect: %v", err)
	} else {
		t.Log("Request to provider succeeded - auto-reconnect working!")
		if respPayload.Message != reqPayload.Message {
			t.Errorf("Expected message %q, got %q", reqPayload.Message, respPayload.Message)
		}
	}

	// Clean up the original provider.
	_ = provider.Close()
}

// TestServerRestartClientReconnects tests that when a server is restarted,
// clients can successfully reconnect and become operational again.
func TestServerRestartClientReconnects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	auth := newMockAuthManager(t)
	provisionToken := "test-provision-token"
	auth.SetProvisionTokens([]string{provisionToken})

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start server on a specific port so we can restart on the same address.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := conn.LocalAddr().String()
	t.Logf("Server address: %s", serverAddr)

	serverCtx, serverCancel := context.WithCancel(ctx)
	serverDone := make(chan struct{})
	go func() {
		_ = server.Serve(serverCtx, conn)
		close(serverDone)
	}()

	// Create client with provision token - will provision automatically.
	clientCreds := NewMemoryCredentialStore(provisionToken, "restart-test-client")
	client, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("initial connection failed: %v", err)
	}

	// Verify client provisioned.
	if clientCreds.NeedsProvisioning() {
		t.Fatal("client should not need provisioning after initial connection")
	}
	originalFP := clientCreds.Fingerprint()
	t.Logf("Client fingerprint: %s", originalFP)

	// Verify client can make requests.
	if err := client.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil); err != nil {
		t.Fatalf("initial request failed: %v", err)
	}
	t.Log("Initial request successful")

	// Stop the server.
	serverCancel()
	_ = conn.Close()
	<-serverDone
	t.Log("Server stopped")

	// Verify client request fails after server stops.
	shortCtx, shortCancel := context.WithTimeout(ctx, 1*time.Second)
	err = client.Request(shortCtx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil)
	shortCancel()
	if err == nil {
		t.Fatal("expected request to fail after server stopped, but it succeeded")
	}
	t.Logf("Request failed after server stop (expected): %v", err)
	_ = client.Close()

	// Restart the server on the same address.
	conn2, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to restart server on same address: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	server2, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	serverCtx2, serverCancel2 := context.WithCancel(ctx)
	defer serverCancel2()
	go func() {
		_ = server2.Serve(serverCtx2, conn2)
	}()

	// Wait a bit for server to be ready.
	time.Sleep(50 * time.Millisecond)
	t.Log("Server restarted")

	// Create new client with the SAME credentials.
	// Since the client already has valid credentials (from provisioning),
	// and the server still recognizes them (same auth manager), it should reconnect.
	client2, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("reconnect after server restart failed: %v", err)
	}
	defer func() { _ = client2.Close() }()

	// Verify the fingerprint is the same (no re-provisioning needed).
	if clientCreds.Fingerprint() != originalFP {
		t.Errorf("expected same fingerprint after reconnect, got different: %s vs %s",
			clientCreds.Fingerprint(), originalFP)
	}

	// Verify client can make requests on the restarted server.
	if err := client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.3"}, nil); err != nil {
		t.Fatalf("request after server restart failed: %v", err)
	}
	t.Log("Client successfully reconnected after server restart")
}

// TestServerRestartWithBoltAuth tests server restart with BoltAuthManager,
// which persists client data across restarts.
func TestServerRestartWithBoltAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create temp directory for bbolt database.
	tempDir, err := os.MkdirTemp("", "qconn-restart-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	provisionToken := "test-provision-token"
	dbPath := filepath.Join(tempDir, "auth.db")

	// Create BoltAuthManager.
	auth, _, err := NewBoltAuthManager(BoltAuthConfig{
		DBPath:          dbPath,
		ServerHostname:  "localhost",
		ProvisionTokens: []string{provisionToken},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create and start server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := conn.LocalAddr().String()
	t.Logf("Server address: %s", serverAddr)

	serverCtx, serverCancel := context.WithCancel(ctx)
	serverDone := make(chan struct{})
	go func() {
		_ = server.Serve(serverCtx, conn)
		close(serverDone)
	}()

	// Create client with provision token.
	clientCreds := NewMemoryCredentialStore(provisionToken, "bolt-restart-client")
	client, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("initial connection failed: %v", err)
	}

	originalFP := clientCreds.Fingerprint()
	t.Logf("Client fingerprint: %s", originalFP)

	// Verify client can make requests.
	if err := client.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.1"}, nil); err != nil {
		t.Fatalf("initial request failed: %v", err)
	}
	t.Log("Initial request successful")
	_ = client.Close()

	// Stop server and close auth manager (simulating full restart).
	serverCancel()
	_ = conn.Close()
	<-serverDone
	auth.Close()
	t.Log("Server stopped and database closed")

	// Restart with a NEW BoltAuthManager pointing to the SAME database.
	// This simulates a full server restart where client data should persist.
	auth2, _, err := NewBoltAuthManager(BoltAuthConfig{
		DBPath:          dbPath,
		ServerHostname:  "localhost",
		ProvisionTokens: []string{provisionToken},
	})
	if err != nil {
		t.Fatalf("failed to reopen auth manager: %v", err)
	}
	defer auth2.Close()

	server2, err := NewServer(ServerOpt{
		Auth:    auth2,
		Clients: auth2,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn2, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to restart server on same address: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	serverCtx2, serverCancel2 := context.WithCancel(ctx)
	defer serverCancel2()
	go func() {
		_ = server2.Serve(serverCtx2, conn2)
	}()

	time.Sleep(50 * time.Millisecond)
	t.Log("Server restarted with new BoltAuthManager")

	// Reconnect with same credentials.
	client2, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       clientCreds,
	})
	if err != nil {
		t.Fatalf("reconnect after server restart failed: %v", err)
	}
	defer func() { _ = client2.Close() }()

	// Verify same fingerprint (client data persisted in database).
	if clientCreds.Fingerprint() != originalFP {
		t.Errorf("expected same fingerprint after restart, got different: %s vs %s",
			clientCreds.Fingerprint(), originalFP)
	}

	// Verify client can make requests.
	if err := client2.Request(ctx, System(), "", &ClientInfoUpdate{MachineIP: "10.0.0.2"}, nil); err != nil {
		t.Fatalf("request after server restart failed: %v", err)
	}
	t.Log("Client successfully reconnected after server restart with BoltAuth persistence")
}
