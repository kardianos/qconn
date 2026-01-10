package qdef

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

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

	// ErrDecodeCSR is returned when a CSR PEM block cannot be decoded.
	ErrDecodeCSR = fmt.Errorf("qconn: failed to decode CSR PEM")

	// ErrDecodeCert is returned when a certificate PEM block cannot be decoded.
	ErrDecodeCert = fmt.Errorf("qconn: failed to decode certificate PEM")

	// ErrRootCANotFound is returned when the root CA certificate is not available.
	ErrRootCANotFound = fmt.Errorf("qconn: root CA not found")

	// ErrNoClientCert is returned when a TLS connection has no client certificate.
	ErrNoClientCert = fmt.Errorf("qconn: no client certificate")

	// ErrNoPeerCert is returned when a connection has no peer certificates.
	ErrNoPeerCert = fmt.Errorf("qconn: no peer certificates")

	// ErrAuthRequired is returned when server requires an authorization manager.
	ErrAuthRequired = fmt.Errorf("qconn: auth is required")

	// ErrInvalidAddress is returned when a client address is invalid for rate limiting.
	ErrInvalidAddress = fmt.Errorf("qconn: invalid client address")

	// ErrFingerprintEmpty is returned when an operation requires a fingerprint but none is provided.
	ErrFingerprintEmpty = fmt.Errorf("qconn: fingerprint is empty")
)

// FingerprintSizeError is returned when a fingerprint has an invalid byte length.
type FingerprintSizeError struct {
	Got int
}

func (e FingerprintSizeError) Error() string {
	return fmt.Sprintf("qconn: fingerprint must be 32 bytes, got %d", e.Got)
}

// CSRHostnameMismatchError is returned when a CSR's CommonName doesn't match the expected hostname.
type CSRHostnameMismatchError struct {
	Got      string
	Expected string
}

func (e CSRHostnameMismatchError) Error() string {
	return fmt.Sprintf("qconn: CSR CommonName %q does not match expected hostname %q", e.Got, e.Expected)
}

// CSRUnauthorizedDNSError is returned when a CSR contains a DNS name that doesn't match the expected hostname.
type CSRUnauthorizedDNSError struct {
	Got      string
	Expected string
}

func (e CSRUnauthorizedDNSError) Error() string {
	return fmt.Sprintf("qconn: CSR contains unauthorized DNS name %q (expected %q)", e.Got, e.Expected)
}

// ClientRevokedError is returned when operations are attempted on a revoked client.
type ClientRevokedError struct {
	Hostname    string
	Fingerprint FP
}

func (e ClientRevokedError) Error() string {
	return fmt.Sprintf("qconn: client %s [%s] is revoked", e.Hostname, e.Fingerprint)
}

// RateLimitError is returned when an operation is rate limited.
type RateLimitError struct {
	Operation string
	Target    string
	Wait      time.Duration
}

func (e RateLimitError) Error() string {
	return fmt.Sprintf("%s: %s for %s: wait %v", ErrRateLimited, e.Operation, e.Target, e.Wait)
}

func (e RateLimitError) Unwrap() error {
	return ErrRateLimited
}

// UnauthorizedRoleError is returned when a role lacks permission for an operation.
type UnauthorizedRoleError struct {
	Roles   []string
	JobType string
}

func (e UnauthorizedRoleError) Error() string {
	return fmt.Sprintf("%s: role %v not authorized to send job type %q", ErrUnauthorized, e.Roles, e.JobType)
}

func (e UnauthorizedRoleError) Unwrap() error {
	return ErrUnauthorized
}

// UnauthorizedTargetError is returned when a target lacks permission to provide a job type.
type UnauthorizedTargetError struct {
	Target  string
	JobType string
}

func (e UnauthorizedTargetError) Error() string {
	return fmt.Sprintf("%s: target %q not authorized to provide job type %q", ErrUnauthorized, e.Target, e.JobType)
}

func (e UnauthorizedTargetError) Unwrap() error {
	return ErrUnauthorized
}

// TargetUnavailableError is returned when a target machine is not available after a timeout.
type TargetUnavailableError struct {
	Target Addr
}

func (e TargetUnavailableError) Error() string {
	return fmt.Sprintf("%s: target %v not available after timeout", ErrTargetNotFound, e.Target)
}

func (e TargetUnavailableError) Unwrap() error {
	return ErrTargetNotFound
}

// MachineNotConnectedError is returned when a target machine is not connected.
type MachineNotConnectedError struct {
	Identity Identity
}

func (e MachineNotConnectedError) Error() string {
	return fmt.Sprintf("%s: machine %s not connected", ErrTargetNotFound, e.Identity)
}

func (e MachineNotConnectedError) Unwrap() error {
	return ErrTargetNotFound
}

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
	// Fingerprint is the SHA-256 hash of the client's certificate.
	Fingerprint FP `cbor:"1,keyasint"`

	// Hostname is the client's declared hostname from provisioning.
	Hostname string `cbor:"2,keyasint"`

	// Address is the client's last known connection address.
	Address netip.AddrPort `cbor:"3,keyasint"`

	// Type is an optional machine type classification.
	Type string `cbor:"4,keyasint,omitempty"`

	// Roles are the authorization roles assigned to this client (server-side only).
	Roles []string `cbor:"5,keyasint,omitempty"`

	// Devices are the device types this client provides.
	Devices []string `cbor:"6,keyasint,omitempty"`
}

func (id Identity) String() string {
	if id.Fingerprint.IsZero() && id.Hostname == "" && !id.Address.IsValid() {
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
// For Server.
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

// CredentialStore handles the persistence of client credentials.
// For Client.
type CredentialStore interface {
	GetIdentity() (Identity, error)
	GetClientCertificate() (tls.Certificate, error)
	GetRootCAs() (*x509.CertPool, error)
	SaveCredentials(id Identity, certPEM, keyPEM []byte) error
	ProvisionToken() string
	OnUpdate() <-chan struct{}
}

// Resolver handles hostname to address resolution.
type Resolver interface {
	Resolve(ctx context.Context, hostname string) (net.Addr, error)
	OnUpdate(hostname string) <-chan struct{}
}

// NetResolver is a default implementation of Resolver using standard net package.
type NetResolver struct{}

func (r NetResolver) Resolve(ctx context.Context, hostname string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", hostname)
}

func (r NetResolver) OnUpdate(hostname string) <-chan struct{} {
	return nil
}
