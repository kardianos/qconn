package qmock

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/kardianos/qconn/qdef"
)

// SimpleFileStore is a filesystem-based implementation of CredentialStore.
type SimpleFileStore struct {
	dir      string
	token    string
	hostname string
	mu       sync.RWMutex
	sig      chan struct{}
}

func NewSimpleFileStore(dir string, token string, hostname string) *SimpleFileStore {
	return &SimpleFileStore{
		dir:      dir,
		token:    token,
		hostname: hostname,
	}
}

func (s *SimpleFileStore) OnUpdate() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sig == nil {
		s.sig = make(chan struct{})
	}
	return s.sig
}

func (s *SimpleFileStore) GetIdentity() (qdef.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(filepath.Join(s.dir, "identity.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return qdef.Identity{Hostname: s.hostname}, nil
		}
		return qdef.Identity{}, qdef.ErrCredentialsMissing
	}
	var id qdef.Identity
	err = json.Unmarshal(data, &id)
	return id, err
}

func (s *SimpleFileStore) GetClientCertificate() (tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certPath := filepath.Join(s.dir, "client.crt")
	keyPath := filepath.Join(s.dir, "client.key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, qdef.ErrCredentialsMissing
	}
	return cert, nil
}

func (s *SimpleFileStore) GetRootCAs() (*x509.CertPool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If we have a local ca.crt, use it.
	caPath := filepath.Join(s.dir, "ca.crt")
	data, err := os.ReadFile(caPath)
	if err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(data) {
			return pool, nil
		}
	}

	// Fallback or error?
	// For now, let's assume it MUST be there if we want to use it.
	return nil, fmt.Errorf("root CA not found in %s", s.dir)
}

func (s *SimpleFileStore) SaveCredentials(id qdef.Identity, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}

	idData, _ := json.Marshal(id)
	if err := os.WriteFile(filepath.Join(s.dir, "identity.json"), idData, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.dir, "client.crt"), certPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.dir, "client.key"), keyPEM, 0600); err != nil {
		return err
	}

	if s.sig != nil {
		close(s.sig)
		s.sig = nil
	}

	return nil
}

func (s *SimpleFileStore) ProvisionToken() string {
	return s.token
}

// SetRootCA allows manually setting the root CA if it's not already in the directory.
func (s *SimpleFileStore) SetRootCA(pem []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "ca.crt"), pem, 0600)
}
