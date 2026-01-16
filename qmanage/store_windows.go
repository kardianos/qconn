//go:build windows

package qmanage

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	"github.com/billgraziano/dpapi"
	"github.com/kardianos/qconn/qdef"
	"golang.org/x/sys/windows/registry"
)

// RegistryCredentialStore implements ClientStore using Windows registry.
// Private keys are encrypted using DPAPI for protection at rest.
//
// Identity (hostname, roles) and provision token are stored in memory only.
// Only certificates and keys are persisted to the registry.
type RegistryCredentialStore struct {
	keyPath  string
	identity qdef.Identity // Hostname and Roles set at init; Fingerprint updated from cert
	token    string        // Provision token set at init

	mu  sync.RWMutex
	sig chan struct{}
}

// NewClientStore creates a new registry-based credential store.
func NewClientStore(cfg ClientStoreConfig, appName string) (ClientStore, error) {
	if err := validateAppName(appName); err != nil {
		return nil, err
	}
	keyPath := registryKeyPath(appName)
	// Create the registry key if it doesn't exist.
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return nil, fmt.Errorf("create registry key: %w", err)
	}
	key.Close()

	s := &RegistryCredentialStore{
		keyPath: keyPath,
		token:   cfg.ProvisionToken,
		identity: qdef.Identity{
			Hostname: cfg.Hostname,
			Roles:    cfg.Roles,
		},
	}
	// Try to load fingerprint from existing certificate.
	if cert, err := s.GetClientCertificate(); err == nil && len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			s.identity.Fingerprint = qdef.FingerprintOf(leaf)
		}
	}
	return s, nil
}

// NewClientStoreWithDir creates a file-based credential store for testing on Windows.
// This allows tests to use temporary directories instead of the registry.
func NewClientStoreWithDir(cfg ClientStoreConfig) (*FileCredentialStore, error) {
	return newFileCredentialStore(cfg)
}

// GetIdentity returns the client identity.
// Hostname and Roles are set at initialization.
// Fingerprint is derived from the stored certificate.
func (s *RegistryCredentialStore) GetIdentity() (qdef.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identity, nil
}

// GetClientCertificate returns the stored client certificate.
func (s *RegistryCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, s.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return tls.Certificate{}, qdef.ErrCredentialsMissing
	}
	defer key.Close()

	certPEM, _, err := key.GetBinaryValue("CertPEM")
	if err != nil {
		return tls.Certificate{}, qdef.ErrCredentialsMissing
	}

	// Key is stored encrypted with DPAPI.
	encryptedKeyPEM, _, err := key.GetBinaryValue("KeyPEM")
	if err != nil {
		return tls.Certificate{}, qdef.ErrCredentialsMissing
	}

	keyPEM, err := dpapi.DecryptBytes(encryptedKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("decrypt private key: %w", err)
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

// GetRootCAs returns the root CA certificate pool.
func (s *RegistryCredentialStore) GetRootCAs() (*x509.CertPool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, s.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("root CA not found")
	}
	defer key.Close()

	caPEM, _, err := key.GetBinaryValue("RootCAPEM")
	if err != nil {
		return nil, fmt.Errorf("root CA not found")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse root CA certificate")
	}
	return pool, nil
}

// SaveCredentials stores the client certificate and private key.
// The private key is encrypted using DPAPI before storage.
// Updates the internal fingerprint from the certificate.
func (s *RegistryCredentialStore) SaveCredentials(certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, s.keyPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer key.Close()

	// Extract fingerprint from certificate and update identity.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	s.identity.Fingerprint = qdef.FingerprintOf(leaf)

	// Write certificate (not encrypted - it's public).
	if err := key.SetBinaryValue("CertPEM", certPEM); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	// Encrypt and write private key using DPAPI.
	encryptedKeyPEM, err := dpapi.EncryptBytes(keyPEM)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}
	if err := key.SetBinaryValue("KeyPEM", encryptedKeyPEM); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	// Signal update.
	if s.sig != nil {
		close(s.sig)
		s.sig = nil
	}

	return nil
}

// ProvisionToken returns the provision token set at initialization.
func (s *RegistryCredentialStore) ProvisionToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

// OnUpdate returns a channel that is closed when credentials are updated.
func (s *RegistryCredentialStore) OnUpdate() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sig == nil {
		s.sig = make(chan struct{})
	}
	return s.sig
}

// SetRootCA stores the root CA certificate.
func (s *RegistryCredentialStore) SetRootCA(certPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, s.keyPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer key.Close()

	return key.SetBinaryValue("RootCAPEM", certPEM)
}

// Close releases resources.
func (s *RegistryCredentialStore) Close() error {
	return nil
}
