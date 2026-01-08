package qdef

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

// StreamHandler defines the application-level logic for handling QUIC streams.
type StreamHandler interface {
	RegisterHandlers(r *StreamRouter)
	Handle(ctx context.Context, id Identity, msg Message, stream Stream)
	OnConnect(conn *quic.Conn)
}

var (
	// ErrCredentialsMissing is returned when the credential store has no valid client certificate.
	ErrCredentialsMissing = fmt.Errorf("qconn: credentials missing")

	// ErrNotConnected is returned when an operation requires an active connection but none exists.
	ErrNotConnected = fmt.Errorf("qconn: not connected")

	// ErrProvisionTokenEmpty is returned when provisioning is attempted without a token.
	ErrProvisionTokenEmpty = fmt.Errorf("qconn: provision token empty")

	// ErrClientRevoked is returned when an operation is attempted on a revoked client.
	ErrClientRevoked = fmt.Errorf("qconn: client revoked")

	// ErrUnknownClient is returned when an operation references an unknown client fingerprint.
	ErrUnknownClient = fmt.Errorf("qconn: unknown client")

	// ErrRateLimited is returned when an operation is rejected due to rate limiting.
	ErrRateLimited = fmt.Errorf("qconn: rate limited")

	// ErrUnauthorized is returned when a client lacks permission for an operation.
	ErrUnauthorized = fmt.Errorf("qconn: unauthorized")

	// ErrTargetNotFound is returned when the target machine is not connected.
	ErrTargetNotFound = fmt.Errorf("qconn: target not found")
)

// ClientStatus represents the authorization state of a client.
type ClientStatus int

const (
	StatusUnprovisioned ClientStatus = iota
	StatusAuthorized
	StatusUnauthorized
	StatusRevoked
)

func (s ClientStatus) String() string {
	switch s {
	case StatusUnprovisioned:
		return "unprovisioned"
	case StatusAuthorized:
		return "authorized"
	case StatusUnauthorized:
		return "unauthorized"
	case StatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// ClientState represents the connection state of a client.
type ClientState int

const (
	StateDisconnected ClientState = iota
	StateProvisioning
	StateProvisioned
	StateConnecting
	StateConnected
	StateAuthorized
	StateRenewing
)

func (s ClientState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateProvisioning:
		return "provisioning"
	case StateProvisioned:
		return "provisioned"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateAuthorized:
		return "authorized"
	case StateRenewing:
		return "renewing"
	default:
		return "unknown"
	}
}

// ServerConnState represents the state of a server-side connection.
type ServerConnState int

const (
	// ConnNew - Connection just accepted, TLS handshake complete.
	ConnNew ServerConnState = iota

	// ConnProvisioning - Client is using provisioning certificate.
	ConnProvisioning

	// ConnPendingAuth - Normal client awaiting authorization approval.
	ConnPendingAuth

	// ConnAuthorized - Client is authorized for normal operations.
	ConnAuthorized

	// ConnDisconnected - Connection closed.
	ConnDisconnected
)

func (s ServerConnState) String() string {
	switch s {
	case ConnNew:
		return "new"
	case ConnProvisioning:
		return "provisioning"
	case ConnPendingAuth:
		return "pending_auth"
	case ConnAuthorized:
		return "authorized"
	case ConnDisconnected:
		return "disconnected"
	default:
		return "unknown"
	}
}

// Identity represents a host's persistent identity.
type Identity struct {
	Hostname    string   `json:"hostname"`
	Address     string   `json:"address"`
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	Roles       []string `json:"roles"`
	Devices     []string `json:"devices"`
}

func (id Identity) String() string {
	if id.Fingerprint == "" && id.Hostname == "" && id.Address == "" {
		return "unknown"
	}
	return fmt.Sprintf("%s (%s, %s)", id.Fingerprint, id.Hostname, id.Address)
}

// MessageID is a unique identifier for a message.
type MessageID int64

// ServiceType represents the type of service being addressed.
type ServiceType int

const (
	ServiceUser ServiceType = iota
	ServiceSystem
	ServiceProvision
)

func (s ServiceType) String() string {
	switch s {
	case ServiceUser:
		return "user"
	case ServiceSystem:
		return "system"
	case ServiceProvision:
		return "provision"
	default:
		return "unknown"
	}
}

// Addr represents a target in the qconn network.
type Addr struct {
	Type    string      `json:"type"`
	Machine string      `json:"machine"`
	Device  string      `json:"device"`
	Service ServiceType `json:"service"`
}

// UserAddr creates an address for a user-level request to a specific machine and job type.
// This is the most common pattern for inter-client communication.
//
// Example: UserAddr("abc123fingerprint", "printer") targets the "printer" handler on machine "abc123fingerprint".
func UserAddr(machine, jobType string) Addr {
	return Addr{
		Service: ServiceUser,
		Machine: machine,
		Type:    jobType,
	}
}

// DeviceAddr creates an address for a user-level request to a specific device on a machine.
// Use this when a machine exposes multiple instances of the same job type.
//
// Example: DeviceAddr("abc123", "printer", "office-printer-1") targets a specific printer.
func DeviceAddr(machine, jobType, device string) Addr {
	return Addr{
		Service: ServiceUser,
		Machine: machine,
		Type:    jobType,
		Device:  device,
	}
}

// SystemAddr creates an address for a system-level request (e.g., renewals, device updates).
// These are typically handled by the server or hub, not forwarded to clients.
//
// Example: SystemAddr("renew") for certificate renewal.
func SystemAddr(method string) Addr {
	return Addr{
		Service: ServiceSystem,
		Type:    method,
	}
}

// Message is the unified envelope for all communication.
type Message struct {
	ID      MessageID       `json:"id"`
	Target  Addr            `json:"target"`
	ReplyTo Addr            `json:"reply_to,omitempty"`
	Error   string          `json:"error,omitempty"`
	Payload cbor.RawMessage `json:"payload"`
}

// HostState represents the known state of a host.
type HostState struct {
	Identity    Identity
	Online      bool
	Provisioned bool
}

// ClientObserver receives lifecycle events and logs.
type ClientObserver interface {
	OnStateChange(id Identity, state ClientState)
	Logf(id Identity, format string, args ...interface{})
}

// StateListener is notified by the server about client connection events.
// This allows anex to track state without a direct server reference.
type StateListener interface {
	OnIdentityConnect(id Identity, conn *quic.Conn)
	OnIdentityDisconnect(id Identity)
	OnStateChange(id Identity, state ClientState)
}

// Stream represents a QUIC stream.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	Context() context.Context
}

// GetStatusFromCert is a helper for auth managers (may be moved to an internal package later if needed).
// AuthorizationManager handles client authorization, role assignment, and certificate issuance.
type AuthorizationManager interface {
	// GetStatus returns the current authorization status of a client certificate.
	GetStatus(cert *x509.Certificate) (ClientStatus, error)

	// GetSignal returns a channel that is closed when the authorization status
	// for the given certificate changes.
	GetSignal(cert *x509.Certificate) <-chan struct{}

	// AuthorizeRoles filters a list of requested roles for a client during provisioning.
	// Authorization is by fingerprint only.
	// Returns the list of permitted roles.
	AuthorizeRoles(fingerprint string, requested []string) []string

	// SignProvisioningCSR signs a CSR for initial client provisioning.
	// The hostname is used for certificate subject; private keys never leave the client.
	SignProvisioningCSR(csrPEM []byte, hostname string) (certPEM []byte, err error)

	// SignRenewalCSR signs a CSR for certificate renewal.
	// The fingerprint identifies the existing client being renewed.
	SignRenewalCSR(csrPEM []byte, fingerprint string) (certPEM []byte, err error)

	// Revoke invalidates the identity, preventing future authorizations or renewals.
	Revoke(id Identity) error

	// RootCert returns the root CA certificate for the network.
	RootCert() *x509.Certificate

	// ServerCertificate returns the TLS certificate for the server to use.
	ServerCertificate() (tls.Certificate, error)
}

// CredentialResponse contains only the certificate; private keys never leave the client.
type CredentialResponse struct {
	CertPEM []byte `cbor:"cert_pem"`
}

// ProvisioningRequest is sent by clients to request initial credentials.
type ProvisioningRequest struct {
	Hostname string `cbor:"hostname"`
	CSRPEM   []byte `cbor:"csr_pem"`
}

// RenewalRequest is sent by clients to renew their certificate.
type RenewalRequest struct {
	CSRPEM []byte `cbor:"csr_pem"`
}

type DeviceUpdateRequest struct {
	Type    string   `cbor:"type"`
	Devices []string `cbor:"devices"`
}
