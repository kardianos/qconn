package qc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/quic-go/quic-go"
)

// ClientStatus represents the authorization state of a client.
type ClientStatus int

const (
	// StatusRevoked indicates the client is not found or explicitly revoked.
	// Connections from these clients will be rejected at the TLS handshake.
	StatusRevoked ClientStatus = iota
	// StatusUnauthorized indicates the client can connect but cannot communicate
	// until its status is promoted.
	StatusUnauthorized
	// StatusAuthorized indicates the client is fully trusted and can communicate.
	StatusAuthorized
)

// AuthorizationManager defines the contract for checking and changing client authorization.
// Server.
type AuthorizationManager interface {
	// GetStatus retrieves the current authorization status for a given client certificate.
	// It should return StatusRevoked if the client is not found or revoked.
	GetStatus(cert *x509.Certificate) (ClientStatus, error)
	// IssueClientCertificate creates a new private key and a signed certificate
	// for the given identity (which will be updated in-place, e.g. with a fingerprint).
	// Status should be set to StatusUnauthorized for the new client.
	// It returns the PEM-encoded certificate and private key.
	IssueClientCertificate(id *Identity) (certPEM []byte, keyPEM []byte, err error)
	// Revoke explicitly revokes a client's access.
	Revoke(id Identity) error
}

type Identity struct {
	Hostname    string `json:"hostname"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// CredentialStore defines the contract for managing the client's cryptographic identity.
// Client.
type CredentialStore interface {
	// GetIdentity returns the client's own identity (hostname).
	GetIdentity() (Identity, error)
	// ProvisionToken returns the token for provisioning a new client.
	ProvisionToken() (string, error)
	// GetClientCertificate loads the client's certificate and private key.
	// Return ErrCredentialsMissing if the credentials are not found and must be provisioned.
	GetClientCertificate() (tls.Certificate, error)
	// GetRootCAs loads the trusted root CA certificate(s) into a cert pool
	// for verifying the server's identity.
	GetRootCAs() (*x509.CertPool, error)
	// SaveCredentials persists the credentials received during provisioning.
	SaveCredentials(id Identity, certPEM, keyPEM []byte) error
}

// Resolver defines the contract for resolving a hostname to a network address.
// Client.
type Resolver interface {
	// Resolve performs a lookup for the given hostname and returns a usable network address.
	Resolve(ctx context.Context, hostname string) (net.Addr, error)
}

// StreamHandler defines the application-level logic for handling QUIC streams.
// Server.
type StreamHandler interface {
	// Handle is called in a new goroutine for each new incoming stream.
	// It should manage the entire lifecycle of the stream.
	Handle(ctx context.Context, stream *quic.Stream)
	// OnConnect is a callback triggered when the client establishes a connection.
	// This is useful for initiating communication from the client side.
	OnConnect(conn *quic.Conn)
}

// ClientState represents the connection state of a client.
type ClientState int

const (
	// StateDisconnected indicates the client is not connected.
	StateDisconnected ClientState = iota
	// StateConnecting indicates the client is attempting to connect or provision.
	StateConnecting
	// StateConnected indicates the client is successfully connected.
	StateConnected
	// StateProvisioning indicates the client is in the process of provisioning credentials.
	StateProvisioning
	// StateProvisioned indicates the client has successfully provisioned credentials.
	StateProvisioned
	// StateAuthorized indicates the client has been authorized by the server.
	StateAuthorized
)

func (s ClientState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateProvisioning:
		return "provisioning"
	case StateProvisioned:
		return "provisioned"
	case StateAuthorized:
		return "authorized"
	default:
		return "unknown"
	}
}

// ClientObserver defines callbacks for monitoring events and logging.
// Client and server.
type ClientObserver interface {
	// OnStateChange is called when the client's or server's connection state changes.
	OnStateChange(id Identity, state ClientState)
	// Logf provides a centralized logging mechanism.
	Logf(id Identity, format string, v ...interface{})
}
