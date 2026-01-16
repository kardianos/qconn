package qmanage

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/netip"
	"time"

	"github.com/kardianos/qconn/qdef"
)

// ClientStore extends qdef.CredentialStore with resource management.
// Identity (hostname, roles) and provision token are set at initialization.
// Only certificates and keys are persisted to storage.
type ClientStore interface {
	qdef.CredentialStore

	// Close releases any resources held by the store.
	Close() error
}

// ClientRecord stores information about a provisioned client.
type ClientRecord struct {
	// Fingerprint is the SHA-256 hash of the client's certificate.
	Fingerprint qdef.FP `cbor:"1,keyasint"`

	// Hostname is the client's declared hostname from provisioning.
	Hostname string `cbor:"2,keyasint"`

	// Status is the client's current authorization status.
	Status qdef.ClientStatus `cbor:"3,keyasint"`

	// CreatedAt is when the client was first provisioned.
	CreatedAt time.Time `cbor:"4,keyasint"`

	// ExpiresAt is when the client's certificate expires.
	ExpiresAt time.Time `cbor:"5,keyasint"`

	// LastAddr is the client's most recent connection address.
	// Updated each time the client connects to the server.
	LastAddr netip.AddrPort `cbor:"6,keyasint"`

	// RequestedRoles is the set of roles the client advertised/requested.
	// These are stored when the client connects, and used when authorizing.
	RequestedRoles []string `cbor:"7,keyasint,omitempty"`

	// Online indicates whether the client is currently connected.
	// Set to true when the client connects, false when it disconnects.
	Online bool `cbor:"8,keyasint"`

	// LastSeen is when the client was last seen (connect or disconnect time).
	LastSeen time.Time `cbor:"9,keyasint"`
}

// ClientFilter specifies criteria for filtering client records.
type ClientFilter struct {
	// Fingerprints limits results to clients with these fingerprints.
	// If empty, no fingerprint filtering is applied.
	Fingerprints []qdef.FP

	// Status limits results to clients with this status.
	// If nil, no status filtering is applied.
	Status *qdef.ClientStatus
}

// AuthManagerConfig configures the AuthManager.
type AuthManagerConfig struct {
	// AppName is used in the storage path.
	AppName string

	// DataDir overrides the default data directory for testing.
	// If empty, uses the platform default.
	DataDir string

	// ServerHostname is the hostname for the server certificate.
	// If empty, defaults to the hostname of the machine.
	ServerHostname string

	// CleanupInterval is how often to run expired client cleanup.
	// If zero, defaults to DefaultCleanupInterval (6 hours).
	// Set to a negative value to disable automatic cleanup.
	CleanupInterval time.Duration

	// BackupInterval is how often to backup the database.
	// If zero or negative, backup is disabled.
	// Backups are saved as auth.db.backup next to the active database.
	BackupInterval time.Duration

	// CACert and CAKey allow injecting an existing CA.
	// If nil, a new CA is created on first run.
	CACert *x509.Certificate
	CAKey  *ecdsa.PrivateKey
}
