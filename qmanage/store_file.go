package qmanage

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
type FileCredentialStore struct {
	dir string
	mu  sync.RWMutex
	sig chan struct{}
}

var _ qdef.CredentialStore = (*FileCredentialStore)(nil)
var _ ClientStore = (*FileCredentialStore)(nil)

// newFileCredentialStore creates a new file-based credential store at the specified directory.
func newFileCredentialStore(dir string) (*FileCredentialStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create client store directory: %w", err)
	}
	return &FileCredentialStore{dir: dir}, nil
}

// GetIdentity returns the stored identity.
func (s *FileCredentialStore) GetIdentity() (qdef.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(filepath.Join(s.dir, "identity.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return qdef.Identity{}, nil
		}
		return qdef.Identity{}, fmt.Errorf("read identity: %w", err)
	}
	var id qdef.Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return qdef.Identity{}, fmt.Errorf("unmarshal identity: %w", err)
	}
	return id, nil
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

// SaveCredentials stores the identity and credentials.
func (s *FileCredentialStore) SaveCredentials(id qdef.Identity, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Extract and validate fingerprint from certificate.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return qdef.ErrDecodeCert
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	id.Fingerprint = qdef.FingerprintOf(leaf)

	// Write identity.
	idData, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(s.dir, "identity.json"), idData, 0600); err != nil {
		return fmt.Errorf("write identity: %w", err)
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

// ProvisionToken returns the stored provision token.
func (s *FileCredentialStore) ProvisionToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(filepath.Join(s.dir, "token"))
	if err != nil {
		return ""
	}
	return string(data)
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

// SetProvisionToken stores the provision token.
func (s *FileCredentialStore) SetProvisionToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	return atomicWriteFile(filepath.Join(s.dir, "token"), []byte(token), 0600)
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
