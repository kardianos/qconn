package qmanage

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/netip"
	"time"

	"github.com/kardianos/qconn/qdef"
)

// ClientStore extends qdef.CredentialStore with additional management methods.
// It provides persistent storage for client credentials, provision tokens, and root CA.
type ClientStore interface {
	qdef.CredentialStore

	// SetProvisionToken stores the provision token used for initial client provisioning.
	// The token is used to authenticate with the server before receiving a signed certificate.
	SetProvisionToken(token string) error

	// SetRootCA stores the root CA certificate in PEM format.
	// This CA is used to verify the server's certificate during TLS handshake.
	SetRootCA(certPEM []byte) error

	// Close releases any resources held by the store.
	Close() error
}

// RoleConfig defines what a role can do.
type RoleConfig struct {
	Provides []string `cbor:"1,keyasint"` // Job types this role provides.
	SendsTo  []string `cbor:"2,keyasint"` // Job types this role can send to.
}

// ClientRecord stores information about a provisioned client.
type ClientRecord struct {
	// Fingerprint is the SHA-256 hash of the client's certificate (hex-encoded).
	Fingerprint string `cbor:"1,keyasint"`

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
}

// AuthManager extends qdef.AuthorizationManager with management capabilities.
// It provides persistent storage for roles, client records, and authorization mappings.
type AuthManager interface {
	qdef.AuthorizationManager

	// SetRoleDef creates or updates a role definition.
	// Roles define what job types a client can provide or send to.
	SetRoleDef(name string, config RoleConfig) error

	// GetRoleDef retrieves a role definition by name.
	// Returns the config and true if found, or an empty config and false if not found.
	GetRoleDef(name string) (RoleConfig, bool)

	// DeleteRoleDef removes a role definition.
	// Existing client authorizations referencing this role are not automatically updated.
	DeleteRoleDef(name string) error

	// ListRoleDefs returns all defined roles as a map of name to config.
	ListRoleDefs() map[string]RoleConfig

	// SetStaticAuthorization assigns roles to a client identified by certificate fingerprint.
	// This determines what the client is allowed to do after connecting.
	SetStaticAuthorization(fingerprint string, roles []string) error

	// GetStaticAuthorization retrieves the roles assigned to a client.
	// Returns nil if the client has no authorizations.
	GetStaticAuthorization(fingerprint string) []string

	// RemoveStaticAuthorization removes all role assignments for a client.
	RemoveStaticAuthorization(fingerprint string) error

	// ListAuthorizations returns all client authorizations as a map of fingerprint to roles.
	ListAuthorizations() map[string][]string

	// SetClientStatus updates a client's authorization status.
	// Use this to authorize, revoke, or change a client's status.
	SetClientStatus(fingerprint string, status qdef.ClientStatus) error

	// UpdateClientAddr updates a client's last known connection address.
	// Call this from a StateListener.OnIdentityConnect handler to track client IPs.
	UpdateClientAddr(fingerprint string, addr netip.AddrPort) error

	// ListClients returns all client records as a map of fingerprint to record.
	ListClients() map[string]ClientRecord

	// Close releases resources and stops background goroutines.
	Close() error
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

	// CACert and CAKey allow injecting an existing CA.
	// If nil, a new CA is created on first run.
	CACert *x509.Certificate
	CAKey  *ecdsa.PrivateKey
}
