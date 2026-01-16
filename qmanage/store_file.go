package qmanage

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/kardianos/qconn/qdef"
)

// FileCredentialStore implements ClientStore using filesystem storage.
// This is the primary implementation on Unix systems and is also used
// for testing on Windows.
//
// Identity (hostname, roles) and provision token are stored in memory only.
// Only certificates and keys are persisted to the filesystem.
type FileCredentialStore struct {
	dir      string
	identity qdef.Identity // Hostname and Roles set at init; Fingerprint updated from cert
	token    string        // Provision token set at init

	mu  sync.RWMutex
	sig chan struct{}
}

var _ qdef.CredentialStore = (*FileCredentialStore)(nil)
var _ ClientStore = (*FileCredentialStore)(nil)

// ClientStoreConfig configures a FileCredentialStore.
type ClientStoreConfig struct {
	// Dir is the directory to store credentials.
	Dir string

	// Hostname is the client's hostname for provisioning.
	Hostname string

	// Roles are the roles this client requests during provisioning.
	Roles []string

	// ProvisionToken is the initial provisioning token.
	ProvisionToken string
}

// newFileCredentialStore creates a new file-based credential store.
func newFileCredentialStore(cfg ClientStoreConfig) (*FileCredentialStore, error) {
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create client store directory: %w", err)
	}
	s := &FileCredentialStore{
		dir:   cfg.Dir,
		token: cfg.ProvisionToken,
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

// GetIdentity returns the client identity.
// Hostname and Roles are set at initialization.
// Fingerprint is derived from the stored certificate.
func (s *FileCredentialStore) GetIdentity() (qdef.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identity, nil
}

// GetClientCertificate returns the stored client certificate.
func (s *FileCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certPath := filepath.Join(s.dir, "client.crt")
	keyPath := filepath.Join(s.dir, "client.key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return tls.Certificate{}, qdef.ErrCredentialsMissing
		}
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return cert, nil
}

// GetRootCAs returns the root CA certificate pool.
func (s *FileCredentialStore) GetRootCAs() (*x509.CertPool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	caPath := filepath.Join(s.dir, "ca.crt")
	data, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, qdef.ErrRootCANotFound
		}
		return nil, fmt.Errorf("qconn: read root CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, qdef.ErrRootCANotFound
	}
	return pool, nil
}

// SaveCredentials stores the client certificate and private key.
// Updates the internal fingerprint from the certificate.
func (s *FileCredentialStore) SaveCredentials(certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Extract fingerprint from certificate and update identity.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return qdef.ErrDecodeCert
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	s.identity.Fingerprint = qdef.FingerprintOf(leaf)

	// Write certificate.
	if err := atomicWriteFile(filepath.Join(s.dir, "client.crt"), certPEM, 0600); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	// Write key.
	if err := atomicWriteFile(filepath.Join(s.dir, "client.key"), keyPEM, 0600); err != nil {
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
func (s *FileCredentialStore) ProvisionToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

// OnUpdate returns a channel that is closed when credentials are updated.
func (s *FileCredentialStore) OnUpdate() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sig == nil {
		s.sig = make(chan struct{})
	}
	return s.sig
}

// SetRootCA stores the root CA certificate.
func (s *FileCredentialStore) SetRootCA(certPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	return atomicWriteFile(filepath.Join(s.dir, "ca.crt"), certPEM, 0600)
}

// Close releases resources.
func (s *FileCredentialStore) Close() error {
	return nil
}

// atomicWriteFile writes data to a temp file and renames it to the target path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	return os.Rename(tmpName, path)
}
