package qconn

import (
	"crypto/tls"
	"crypto/x509"
)

// CredentialStore manages client credentials for connecting to a qconn server.
// Identity (hostname) and provision token are set at initialization.
// Certificates, keys, and root CA are persisted to storage.
type CredentialStore interface {
	// TLSConfig returns the TLS configuration for connecting.
	// If no credentials exist, returns a provisioning TLS config.
	TLSConfig() (*tls.Config, error)

	// NeedsProvisioning returns true if the client needs to provision credentials.
	NeedsProvisioning() bool

	// ProvisionToken returns the provisioning token.
	ProvisionToken() string

	// Hostname returns the client's hostname for provisioning.
	Hostname() string

	// SaveCredentials stores credentials after successful provisioning.
	SaveCredentials(certPEM, keyPEM, rootCAPEM []byte) error

	// GetClientCertificate returns the stored client certificate and key.
	// Returns an error if no credentials exist.
	GetClientCertificate() (tls.Certificate, error)

	// GetRootCAs returns the root CA certificate pool for server verification.
	GetRootCAs() (*x509.CertPool, error)

	// Fingerprint returns the client's certificate fingerprint.
	// Returns zero FP if no credentials exist.
	Fingerprint() FP

	// Close releases any resources held by the store.
	Close() error
}

// ClientStoreConfig configures a client credential store.
type ClientStoreConfig struct {
	// Dir is the directory to store credentials (for file-based stores).
	Dir string

	// Hostname is the client's hostname for provisioning.
	Hostname string

	// ProvisionToken is the initial provisioning token.
	ProvisionToken string
}
