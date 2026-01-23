package qconn

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/kardianos/qconn/qstore"
)

// Well-known keys used by ClientCredential for credential storage.
const (
	KeyCert = "cert" // Client certificate PEM
	KeyKey  = "key"  // Client private key PEM
	KeyCA   = "ca"   // CA certificate PEM
)

// ClientCredential implements CredentialStore using a DataStore backend.
// This separates auth/TLS logic from storage implementation.
type ClientCredential struct {
	store    qstore.DataStore
	hostname string
	token    string

	mu          sync.RWMutex
	fingerprint FP
	expiresAt   time.Time // Cached certificate expiry time
	sig         chan struct{}
}

var _ CredentialStore = (*ClientCredential)(nil)

// ClientCredentialConfig configures a ClientCredential.
type ClientCredentialConfig struct {
	// Store is the underlying data store.
	Store qstore.DataStore

	// Hostname is the client's hostname for provisioning.
	Hostname string

	// ProvisionToken is the initial provisioning token.
	ProvisionToken string
}

// NewClientCredential creates a new credential store with the given data store backend.
func NewClientCredential(cfg ClientCredentialConfig) (*ClientCredential, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("data store is required")
	}

	s := &ClientCredential{
		store:    cfg.Store,
		hostname: cfg.Hostname,
		token:    cfg.ProvisionToken,
	}

	// Try to load fingerprint and expiry from existing certificate.
	if cert, err := s.GetClientCertificate(); err == nil && len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			s.fingerprint = FingerprintOf(leaf)
			s.expiresAt = leaf.NotAfter
		}
	}

	return s, nil
}

// TLSConfig returns the TLS configuration for connecting.
func (s *ClientCredential) TLSConfig() (*tls.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Use existing credentials if we have them and they haven't expired.
	if !s.expiresAt.IsZero() && !timeNow().After(s.expiresAt) {
		cert, err := s.getClientCertificateLocked()
		if err == nil {
			rootCAs, err := s.getRootCAsLocked()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            rootCAs,
				InsecureSkipVerify: true, // Server hostname may differ
				NextProtos:         []string{"qconn"},
				Time:               timeNow, // Use fake time in tests
			}, nil
		}
	}

	// No credentials or expired, build provisioning TLS config.
	// Require minimum token length to prevent accidental use of empty/short tokens.
	if len(s.token) < 12 {
		return nil, ErrTokenTooShort
	}

	derivedCA, err := GenerateDerivedCA(s.token)
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
		ServerName:   ProvisioningServerName(s.token),
		NextProtos:   []string{"qconn"},
		Time:         timeNow, // Use fake time in tests
	}, nil
}

// NeedsProvisioning returns true if the client needs to provision credentials.
// This includes when no certificate exists or when the certificate has expired.
func (s *ClientCredential) NeedsProvisioning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// No certificate loaded or expiry not set means we need to provision.
	if s.expiresAt.IsZero() {
		return true
	}
	// Check if certificate has expired.
	return timeNow().After(s.expiresAt)
}

// ProvisionToken returns the provisioning token.
func (s *ClientCredential) ProvisionToken() string {
	return s.token
}

// Hostname returns the client's hostname for provisioning.
func (s *ClientCredential) Hostname() string {
	return s.hostname
}

// SaveCredentials stores credentials after successful provisioning.
func (s *ClientCredential) SaveCredentials(certPEM, keyPEM, rootCAPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Extract fingerprint from certificate.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("decode certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// Save to underlying store. Encrypt the private key.
	if err := s.store.Set(KeyCert, false, certPEM); err != nil {
		return fmt.Errorf("save cert: %w", err)
	}
	if err := s.store.Set(KeyKey, true, keyPEM); err != nil {
		return fmt.Errorf("save key: %w", err)
	}
	if err := s.store.Set(KeyCA, false, rootCAPEM); err != nil {
		return fmt.Errorf("save ca: %w", err)
	}

	s.fingerprint = FingerprintOf(leaf)
	s.expiresAt = leaf.NotAfter

	// Signal update.
	if s.sig != nil {
		close(s.sig)
		s.sig = nil
	}

	return nil
}

// GetClientCertificate returns the stored client certificate and key.
func (s *ClientCredential) GetClientCertificate() (tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getClientCertificateLocked()
}

func (s *ClientCredential) getClientCertificateLocked() (tls.Certificate, error) {
	certPEM, err := s.store.Get(KeyCert, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := s.store.Get(KeyKey, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return tls.Certificate{}, ErrNoCert
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// GetRootCAs returns the root CA certificate pool for server verification.
func (s *ClientCredential) GetRootCAs() (*x509.CertPool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getRootCAsLocked()
}

func (s *ClientCredential) getRootCAsLocked() (*x509.CertPool, error) {
	caPEM, err := s.store.Get(KeyCA, false)
	if err != nil {
		return nil, err
	}
	if len(caPEM) == 0 {
		return nil, ErrNoCert
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse root CA")
	}
	return pool, nil
}

// Fingerprint returns the client's certificate fingerprint.
func (s *ClientCredential) Fingerprint() FP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fingerprint
}

// OnUpdate returns a channel that is closed when credentials are updated.
func (s *ClientCredential) OnUpdate() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sig == nil {
		s.sig = make(chan struct{})
	}
	return s.sig
}

// Close releases any resources held by the store.
func (s *ClientCredential) Close() error {
	return nil
}

// Store returns the underlying data store.
func (s *ClientCredential) Store() qstore.DataStore {
	return s.store
}

// FileCredentialStore implements CredentialStore using filesystem storage.
// This is a convenience wrapper that combines FileDataStore with ClientCredential.
type FileCredentialStore struct {
	*ClientCredential
	dataStore *qstore.FileDataStore
}

var _ CredentialStore = (*FileCredentialStore)(nil)

// NewFileCredentialStore creates a new file-based credential store.
func NewFileCredentialStore(cfg ClientStoreConfig) (*FileCredentialStore, error) {
	dataStore, err := qstore.NewFileDataStore(cfg.Dir)
	if err != nil {
		return nil, err
	}

	cred, err := NewClientCredential(ClientCredentialConfig{
		Store:          dataStore,
		Hostname:       cfg.Hostname,
		ProvisionToken: cfg.ProvisionToken,
	})
	if err != nil {
		return nil, err
	}

	return &FileCredentialStore{
		ClientCredential: cred,
		dataStore:        dataStore,
	}, nil
}

// DataStore returns the underlying FileDataStore.
func (s *FileCredentialStore) DataStore() *qstore.FileDataStore {
	return s.dataStore
}
