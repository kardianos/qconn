package qconn

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileCredentialStore implements CredentialStore using filesystem storage.
// Identity (hostname) and provision token are stored in memory only.
// Certificates, keys, and root CA are persisted to the filesystem.
type FileCredentialStore struct {
	dir      string
	hostname string
	token    string

	mu          sync.RWMutex
	fingerprint FP
	sig         chan struct{}
}

var _ CredentialStore = (*FileCredentialStore)(nil)

// NewFileCredentialStore creates a new file-based credential store.
func NewFileCredentialStore(cfg ClientStoreConfig) (*FileCredentialStore, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("directory is required")
	}
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create credential store directory: %w", err)
	}

	s := &FileCredentialStore{
		dir:      cfg.Dir,
		hostname: cfg.Hostname,
		token:    cfg.ProvisionToken,
	}

	// Try to load fingerprint from existing certificate.
	if cert, err := s.GetClientCertificate(); err == nil && len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			s.fingerprint = FingerprintOf(leaf)
		}
	}

	return s, nil
}

// TLSConfig returns the TLS configuration for connecting.
func (s *FileCredentialStore) TLSConfig() (*tls.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, err := s.getClientCertificateLocked()
	if err == nil {
		// Have credentials, use them.
		rootCAs, err := s.getRootCAsLocked()
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            rootCAs,
			InsecureSkipVerify: true, // Server hostname may differ
			NextProtos:         []string{"qconn"},
		}, nil
	}

	// No credentials, build provisioning TLS config.
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
	}, nil
}

// NeedsProvisioning returns true if the client needs to provision credentials.
func (s *FileCredentialStore) NeedsProvisioning() bool {
	_, err := s.GetClientCertificate()
	return err != nil
}

// ProvisionToken returns the provisioning token.
func (s *FileCredentialStore) ProvisionToken() string {
	return s.token
}

// Hostname returns the client's hostname for provisioning.
func (s *FileCredentialStore) Hostname() string {
	return s.hostname
}

// SaveCredentials stores credentials after successful provisioning.
func (s *FileCredentialStore) SaveCredentials(certPEM, keyPEM, rootCAPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Extract fingerprint from certificate.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("decode certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	s.fingerprint = FingerprintOf(leaf)

	// Write root CA.
	if err := atomicWriteFile(filepath.Join(s.dir, "ca.crt"), rootCAPEM, 0600); err != nil {
		return fmt.Errorf("write root CA: %w", err)
	}

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

// GetClientCertificate returns the stored client certificate and key.
func (s *FileCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getClientCertificateLocked()
}

func (s *FileCredentialStore) getClientCertificateLocked() (tls.Certificate, error) {
	certPath := filepath.Join(s.dir, "client.crt")
	keyPath := filepath.Join(s.dir, "client.key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return tls.Certificate{}, ErrNoCert
		}
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return cert, nil
}

// GetRootCAs returns the root CA certificate pool for server verification.
func (s *FileCredentialStore) GetRootCAs() (*x509.CertPool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getRootCAsLocked()
}

func (s *FileCredentialStore) getRootCAsLocked() (*x509.CertPool, error) {
	caPath := filepath.Join(s.dir, "ca.crt")
	data, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoCert
		}
		return nil, fmt.Errorf("read root CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("parse root CA")
	}
	return pool, nil
}

// Fingerprint returns the client's certificate fingerprint.
func (s *FileCredentialStore) Fingerprint() FP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fingerprint
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

// Close releases any resources held by the store.
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
