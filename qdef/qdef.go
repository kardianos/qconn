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
	default:
		return "unknown"
	}
}

// Identity represents a host's persistent identity.
type Identity struct {
	Hostname    string   `json:"hostname"`
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	Devices     []string `json:"devices"`
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
	Identity Identity
	Online   bool
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
type AuthorizationManager interface {
	GetStatus(cert *x509.Certificate) (ClientStatus, error)
	GetSignal(cert *x509.Certificate) <-chan struct{}
	IssueClientCertificate(id *Identity) (certPEM []byte, keyPEM []byte, err error)
	RenewClientCertificate(id *Identity) (certPEM []byte, keyPEM []byte, err error)
	Revoke(id Identity) error
	RootCert() *x509.Certificate
	ServerCertificate() (tls.Certificate, error)
}

type CredentialResponse struct {
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
}

type DeviceUpdateRequest struct {
	Type    string   `json:"type"`
	Devices []string `json:"devices"`
}
