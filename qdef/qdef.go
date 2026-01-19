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
)

// Default CBOR message size limits.
const (
	// DefaultMaxMessageSize is the default maximum size for CBOR messages (1MB).
	DefaultMaxMessageSize = 1 << 20

	// ProvisioningMaxMessageSize is the maximum size for provisioning messages (64KB).
	// Provisioning messages only contain CSR and hostname, so should be small.
	ProvisioningMaxMessageSize = 64 << 10
)

// decMode is the CBOR decoder mode used throughout the package.
var decMode cbor.DecMode

func init() {
	var err error
	decMode, err = cbor.DecOptions{
		MaxArrayElements: 1024,
		MaxMapPairs:      1024,
		MaxNestedLevels:  32,
	}.DecModeWithTags(cbor.NewTagSet())
	if err != nil {
		panic(fmt.Sprintf("qdef: failed to create CBOR decoder mode: %v", err))
	}
}

// NewDecoder creates a CBOR decoder with the specified maximum message size.
// If maxSize is 0, DefaultMaxMessageSize is used.
func NewDecoder(r io.Reader, maxSize int) *cbor.Decoder {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	return decMode.NewDecoder(io.LimitReader(r, int64(maxSize)))
}

// MessageRouter routes ServiceUser messages to external systems (e.g., gRPC).
// The server tries local qconn clients first, then delegates to MessageRouter.
type MessageRouter interface {
	// RouteMessage routes a message to target. Return ErrNotHandled if not handled.
	RouteMessage(ctx context.Context, sender Identity, msg Message) (*Message, error)

	// ListTargets returns external targets that can receive messages.
	// Used by list-clients to include external systems in the client list.
	ListTargets(filterFP []FP) []ClientInfo
}

// ConnectionObserver receives connection lifecycle events.
// Used by bridges to track connected clients.
type ConnectionObserver interface {
	OnConnect(id Identity)
	OnDisconnect(id Identity)
	OnDeviceUpdate(id Identity, devices []DeviceInfo)
}

// MessageState represents the state of a message as it flows through the system.
// States are linear and progress forward only.
type MessageState int8

const (
	// MsgStateUnsent - Message created but not yet sent.
	MsgStateUnsent MessageState = iota

	// MsgStateSent - Message sent by client to server.
	MsgStateSent

	// MsgStateServerReceived - Server received the message.
	MsgStateServerReceived

	// MsgStateResolvedMachine - Server found the target machine.
	MsgStateResolvedMachine

	// MsgStateResolvedDevice - Server found the target device (if specified).
	MsgStateResolvedDevice

	// MsgStateSentToTarget - Server sent message to target client.
	MsgStateSentToTarget

	// MsgStateTargetAck - Target client acknowledged receipt (triggers job timeout).
	MsgStateTargetAck

	// MsgStateTargetResponse - Target client sent response.
	MsgStateTargetResponse

	// MsgStateForwardedResponse - Server forwarded response to sender.
	MsgStateForwardedResponse

	// MsgStateClientReceived - Sender client received the response.
	MsgStateClientReceived
)

// MessageAction indicates the purpose of a message.
type MessageAction int8

const (
	// MsgActionDeliver is a normal message delivery (request or response).
	MsgActionDeliver MessageAction = iota

	// MsgActionAck is an acknowledgment from the target.
	// When received, the server transitions from resolution timeout to job timeout.
	MsgActionAck

	// MsgActionStatusUpdate is a status update from server to sender.
	// Status updates inform the sender of message progress without completing the request.
	MsgActionStatusUpdate
)

func (a MessageAction) String() string {
	switch a {
	case MsgActionDeliver:
		return "deliver"
	case MsgActionAck:
		return "ack"
	case MsgActionStatusUpdate:
		return "status_update"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

func (s MessageState) String() string {
	switch s {
	case MsgStateUnsent:
		return "unsent"
	case MsgStateSent:
		return "sent"
	case MsgStateServerReceived:
		return "server_received"
	case MsgStateResolvedMachine:
		return "resolved_machine"
	case MsgStateResolvedDevice:
		return "resolved_device"
	case MsgStateSentToTarget:
		return "sent_to_target"
	case MsgStateTargetAck:
		return "target_ack"
	case MsgStateTargetResponse:
		return "target_response"
	case MsgStateForwardedResponse:
		return "forwarded_response"
	case MsgStateClientReceived:
		return "client_received"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// MessageObserver receives message lifecycle events for observability.
type MessageObserver interface {
	// OnMessageComplete is called when a message completes (success or failure).
	// src is the sender identity, dest is the target address.
	// lastState is the final state reached before completion or error.
	// duration is the total time from server receipt to completion.
	// err is nil on success, or the error that caused failure.
	OnMessageComplete(src Identity, dest Addr, msgID MessageID, lastState MessageState, duration time.Duration, err error)
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

	// ErrDuplicateHostname is returned when authorizing a client whose hostname
	// is already used by another authorized client. Hostnames must be unique
	// among authorized clients because messages are routed by hostname.
	ErrDuplicateHostname = fmt.Errorf("qconn: duplicate hostname")

	// ErrRateLimited is returned when an operation is rejected due to rate limiting.
	ErrRateLimited = fmt.Errorf("qconn: rate limited")

	// ErrUnauthorized is returned when a client lacks permission for an operation.
	ErrUnauthorized = fmt.Errorf("qconn: unauthorized")

	// ErrTargetNotFound is returned when the target machine is not connected.
	ErrTargetNotFound = fmt.Errorf("qconn: target not found")

	// ErrNotHandled is returned by MessageRouter when it doesn't handle a target.
	ErrNotHandled = fmt.Errorf("qconn: not handled")

	// ErrInvalidAction is returned when a message has an invalid action for its context.
	ErrInvalidAction = fmt.Errorf("qconn: invalid message action")

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
	return fmt.Sprintf("qconn: fingerprint must be %d bytes, got %d", fpSize, e.Got)
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
	Target  FP
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

// ErrPayloadTooLarge is returned when a message payload exceeds the configured limit.
var ErrPayloadTooLarge = fmt.Errorf("qconn: payload too large")

// PayloadTooLargeError provides details about the payload size violation.
type PayloadTooLargeError struct {
	JobType string
	Size    int
	Limit   int
}

func (e PayloadTooLargeError) Error() string {
	return fmt.Sprintf("%s: payload size %d exceeds limit %d for job type %q",
		ErrPayloadTooLarge, e.Size, e.Limit, e.JobType)
}

func (e PayloadTooLargeError) Unwrap() error {
	return ErrPayloadTooLarge
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

// ErrDeviceNotFound is returned when a target device is not found on the machine.
var ErrDeviceNotFound = fmt.Errorf("qconn: device not found")

// DeviceNotFoundError is returned when a target device is not declared by the machine.
type DeviceNotFoundError struct {
	Machine  FP
	DeviceID string
}

func (e DeviceNotFoundError) Error() string {
	return fmt.Sprintf("%s: device %q not found on machine %s", ErrDeviceNotFound, e.DeviceID, e.Machine)
}

func (e DeviceNotFoundError) Unwrap() error {
	return ErrDeviceNotFound
}

// DuplicateHostnameError is returned when authorizing a client whose hostname
// is already used by another authorized client.
type DuplicateHostnameError struct {
	Hostname            string
	ExistingFingerprint FP
}

func (e DuplicateHostnameError) Error() string {
	return fmt.Sprintf("%s: hostname %q is already used by client %s", ErrDuplicateHostname, e.Hostname, e.ExistingFingerprint)
}

func (e DuplicateHostnameError) Unwrap() error {
	return ErrDuplicateHostname
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
		return "connected/not-authorized"
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
}

func (id Identity) String() string {
	if id.Fingerprint.IsZero() && id.Hostname == "" && !id.Address.IsValid() {
		return "unknown"
	}
	return fmt.Sprintf("%s (%s, %s)", id.Fingerprint, id.Hostname, id.Address)
}

// RoleConfig defines what a role can do.
type RoleConfig struct {
	Provides []string `cbor:"1,keyasint"` // Job types this role provides.
	SendsTo  []string `cbor:"2,keyasint"` // Job types this role can send to.
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
	Machine FP          `json:"machine"`
	Device  string      `json:"device"`
	Service ServiceType `json:"service"`
}

// UserAddr creates an address for a user-level request to a specific machine and job type.
// This is the most common pattern for inter-client communication.
//
// Example: UserAddr("abc123fingerprint", "printer") targets the "printer" handler on machine "abc123fingerprint".
func UserAddr(machine FP, jobType string) Addr {
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
func DeviceAddr(machine FP, jobType, device string) Addr {
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

	// State is the current message state (used in status updates).
	State MessageState `json:"state,omitempty"`

	// Action indicates the purpose of this message (Deliver, Ack, StatusUpdate).
	Action MessageAction `json:"action,omitempty"`
}

// ClientObserver receives lifecycle events and logs.
type ClientObserver interface {
	OnStateChange(id Identity, state ClientState)
	Logf(id Identity, format string, args ...any)
}

// AuthorizationManager handles client authorization and certificate issuance.
// For Server.
type AuthorizationManager interface {
	// GetStatus returns the current authorization status of a client.
	GetStatus(fp FP) (ClientStatus, error)

	// WaitFor blocks until the authorization status changes or context is cancelled.
	// Returns ctx.Err() on context cancellation, nil if status changed.
	WaitFor(ctx context.Context, fp FP) error

	// SignProvisioningCSR signs a CSR for initial client provisioning.
	// The hostname is used for certificate subject; private keys never leave the client.
	// The roles are the client's requested roles, stored for later authorization.
	SignProvisioningCSR(csrPEM []byte, hostname string, roles []string) (certPEM []byte, err error)

	// SignRenewalCSR signs a CSR for certificate renewal.
	// The fingerprint identifies the existing client being renewed.
	SignRenewalCSR(csrPEM []byte, fp FP) (certPEM []byte, err error)

	// RootCert returns the root CA certificate for the network.
	RootCert() *x509.Certificate

	// ServerCertificate returns the TLS certificate for the server to use.
	ServerCertificate() (tls.Certificate, error)

	// UpdateClientAddr updates a client's address, marks them online, and sets hostname if empty.
	// If offline, addr and hostnames are ignored.
	UpdateClientAddr(fp FP, online bool, addr netip.AddrPort, hostname string) error

	// SetClientStatus updates a client's status.
	SetClientStatus(fp FP, status ClientStatus) error

	// ListClientsInfo returns clients as ClientInfo.
	// If showUnauthorized is false, only authorized clients are returned.
	// If fingerprints is non-empty, only clients with matching fingerprints are returned.
	ListClientsInfo(showUnauthorized bool, fingerprints []FP) []ClientInfo
}

// CredentialResponse contains the certificate and optionally the root CA.
// Private keys never leave the client.
type CredentialResponse struct {
	CertPEM   []byte `cbor:"cert_pem"`
	RootCAPEM []byte `cbor:"root_ca_pem,omitempty"` // Server's root CA for future verification.
}

// ProvisioningRequest is sent by clients to request initial credentials.
type ProvisioningRequest struct {
	Hostname string   `cbor:"hostname"`
	CSRPEM   []byte   `cbor:"csr_pem"`
	Roles    []string `cbor:"roles,omitempty"`
}

// RenewalRequest is sent by clients to renew their certificate.
type RenewalRequest struct {
	CSRPEM []byte `cbor:"csr_pem"`
}

// DeviceInfo describes a device provided by a client.
// Used both for device updates from clients and in client listings.
// A machine can have multiple service types (e.g., "printer" and "import-results"),
// and each device specifies which service type it belongs to.
type DeviceInfo struct {
	ID           string    `cbor:"id"`            // Unique device identifier (e.g., "P1")
	Name         string    `cbor:"name"`          // Human-readable name
	ServiceType  string    `cbor:"service_type"`  // Service type (e.g., "printer", "import-results")
	DeviceType   string    `cbor:"device_type"`   // Device subtype (e.g., "network", "usb")
	SerialNumber string    `cbor:"serial_number"` // Hardware serial number
	Online       bool      `cbor:"online"`        // Whether device is currently online
	LastSeen     time.Time `cbor:"last_seen"`     // When device was last seen
}

// DeviceUpdateRequest sends the complete list of devices for a machine.
// Each device specifies its service type, allowing a machine to provide
// multiple service types (e.g., printer and import-results).
type DeviceUpdateRequest struct {
	Devices   []DeviceInfo `cbor:"devices"` // All devices with their service types
	Hostname  string       // Hostname.
	LocalAddr netip.Addr   // Local address in case client is behind a NAT for local identification.
}

// CredentialStore handles the persistence of client credentials.
// Identity (hostname, roles) and provision token are set at initialization.
// Only certificates and keys are persisted to storage.
type CredentialStore interface {
	// GetIdentity returns the client identity.
	// Hostname and Roles are set at initialization.
	// Fingerprint is derived from the stored certificate (zero if no cert).
	GetIdentity() (Identity, error)

	// GetClientCertificate returns the stored client certificate and key.
	GetClientCertificate() (tls.Certificate, error)

	// GetRootCAs returns the root CA certificate pool for server verification.
	GetRootCAs() (*x509.CertPool, error)

	// SetRootCA stores the root CA certificate (received during provisioning).
	SetRootCA(certPEM []byte) error

	// SaveCredentials stores the client certificate and private key.
	// The fingerprint in GetIdentity() will be updated from this certificate.
	SaveCredentials(certPEM, keyPEM []byte) error

	// ProvisionToken returns the provision token set at initialization.
	ProvisionToken() string

	// OnUpdate returns a channel that is closed when credentials are updated.
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
