package qconn

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"time"
)

// MemoryCredentialStore is an in-memory CredentialStore for testing.
type MemoryCredentialStore struct {
	token    string
	hostname string

	mu          sync.RWMutex
	certPEM     []byte
	keyPEM      []byte
	rootCAPEM   []byte
	fingerprint FP
	expiresAt   time.Time
}

var _ CredentialStore = (*MemoryCredentialStore)(nil)

// NewMemoryCredentialStore creates a CredentialStore that provisions with the given token.
func NewMemoryCredentialStore(token, hostname string) *MemoryCredentialStore {
	return &MemoryCredentialStore{
		token:    token,
		hostname: hostname,
	}
}

// NewMemoryCredentialStoreWithCreds creates a CredentialStore with existing credentials.
func NewMemoryCredentialStoreWithCreds(certPEM, keyPEM, rootCAPEM []byte) *MemoryCredentialStore {
	s := &MemoryCredentialStore{
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		rootCAPEM: rootCAPEM,
	}
	// Extract fingerprint and expiry from certificate.
	if block, _ := pem.Decode(certPEM); block != nil {
		if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
			s.fingerprint = FingerprintOf(leaf)
			s.expiresAt = leaf.NotAfter
		}
	}
	return s
}

func (m *MemoryCredentialStore) TLSConfig() (*tls.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Use existing credentials if we have them and they haven't expired.
	if !m.expiresAt.IsZero() && !timeNow().After(m.expiresAt) {
		cert, err := tls.X509KeyPair(m.certPEM, m.keyPEM)
		if err != nil {
			return nil, err
		}
		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(m.rootCAPEM)
		return &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            rootCAs,
			InsecureSkipVerify: true, // Server hostname may differ
			NextProtos:         []string{"qconn"},
			Time:               timeNow, // Use fake time in tests
		}, nil
	}

	// No credentials or expired, build provisioning TLS config.
	derivedCA, err := GenerateDerivedCA(m.token)
	if err != nil {
		return nil, err
	}

	provisioningCert, err := GenerateProvisioningIdentity(derivedCA)
	if err != nil {
		return nil, err
	}

	derivedCACert, err := x509.ParseCertificate(derivedCA.Certificate[0])
	if err != nil {
		return nil, err
	}
	provisionPool := x509.NewCertPool()
	provisionPool.AddCert(derivedCACert)

	return &tls.Config{
		Certificates: []tls.Certificate{provisioningCert},
		RootCAs:      provisionPool,
		ServerName:   ProvisioningServerName(m.token),
		NextProtos:   []string{"qconn"},
		Time:         timeNow, // Use fake time in tests
	}, nil
}

func (m *MemoryCredentialStore) NeedsProvisioning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.expiresAt.IsZero() {
		return true
	}
	return timeNow().After(m.expiresAt)
}

func (m *MemoryCredentialStore) ProvisionToken() string {
	return m.token
}

func (m *MemoryCredentialStore) Hostname() string {
	return m.hostname
}

func (m *MemoryCredentialStore) SaveCredentials(certPEM, keyPEM, rootCAPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.certPEM = certPEM
	m.keyPEM = keyPEM
	m.rootCAPEM = rootCAPEM

	// Extract fingerprint and expiry from certificate.
	if block, _ := pem.Decode(certPEM); block != nil {
		if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
			m.fingerprint = FingerprintOf(leaf)
			m.expiresAt = leaf.NotAfter
		}
	}
	return nil
}

func (m *MemoryCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.certPEM == nil {
		return tls.Certificate{}, ErrNoCert
	}
	return tls.X509KeyPair(m.certPEM, m.keyPEM)
}

func (m *MemoryCredentialStore) GetRootCAs() (*x509.CertPool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.rootCAPEM == nil {
		return nil, ErrNoCert
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(m.rootCAPEM)
	return pool, nil
}

func (m *MemoryCredentialStore) Fingerprint() FP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fingerprint
}

func (m *MemoryCredentialStore) Close() error {
	return nil
}

// CertPEM returns the stored certificate PEM (for testing/inspection).
func (m *MemoryCredentialStore) CertPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certPEM
}
