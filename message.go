package qconn

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kardianos/qconn/bech32"
	"golang.org/x/crypto/blake2b"
)

// SystemMachine is the special machine name for system commands.
const SystemMachine = "$system"

// Admin message types that should be restricted.
const AdminPrefix = "admin/"

// Can only access admin prefix on system.
const AdminRole = "admin"

// Target identifies the destination for a message.
// At least one of Machine, Device, or DeviceType must be set.
// If Device is set, Machine must also be set.
// If Device is set, DeviceType is ignored.
type Target struct {
	Machine    string `cbor:"1,keyasint,omitempty"` // Machine name, "$system" for system commands
	Device     string `cbor:"2,keyasint,omitempty"` // Device name (requires Machine)
	DeviceType string `cbor:"3,keyasint,omitempty"` // Device type (ignored if Device is set)
}

func IsAdminMessageType(msgType string) bool {
	return strings.HasPrefix(msgType, AdminPrefix)
}

// System returns a Target for system commands.
func System() Target {
	return Target{Machine: SystemMachine}
}

// ToMachine returns a Target for a specific machine.
func ToMachine(machine string) Target {
	return Target{Machine: machine}
}

// ToDevice returns a Target for a specific device on a machine.
func ToDevice(machine, device string) Target {
	return Target{Machine: machine, Device: device}
}

// ToType returns a Target for any device of a given type.
func ToType(deviceType string) Target {
	return Target{DeviceType: deviceType}
}

// IsSystem returns true if this targets the system.
func (t Target) IsSystem() bool {
	return t.Machine == SystemMachine
}

// IsZero returns true if no targeting fields are set.
func (t Target) IsZero() bool {
	return t.Machine == "" && t.Device == "" && t.DeviceType == ""
}

// Validate checks that the target is valid.
func (t Target) Validate() error {
	if t.IsZero() {
		return ErrInvalidTarget
	}
	if t.Device != "" && t.Machine == "" {
		return ErrDeviceRequiresMachine
	}
	return nil
}

// String returns a human-readable representation of the target.
func (t Target) String() string {
	if t.Device != "" {
		return t.Machine + "/" + t.Device
	}
	if t.Machine != "" {
		return t.Machine
	}
	return "type:" + t.DeviceType
}

// DeviceInfo describes a device on a machine.
type DeviceInfo struct {
	Name string `cbor:"1,keyasint"` // Unique name within the machine
	Type string `cbor:"2,keyasint"` // Device type (e.g., "printer", "import", "export")
}

const taPrefix = "qt"
const taSize = 24

type TA [taSize]byte

func (ta TA) String() string {
	s, err := bech32.Encode(taPrefix, ta[:])
	if err != nil {
		panic("bech32 encode TA: " + err.Error())
	}
	return s
}

// IsZero returns true if zero value.
func (ta TA) IsZero() bool {
	return ta == TA{}
}

func ParseTA(s string) (TA, error) {
	prefix, body, err := bech32.Decode(s)
	if err != nil {
		return TA{}, err
	}
	if prefix != taPrefix {
		return TA{}, fmt.Errorf("incorrect token type, got type %q want type %q", prefix, taPrefix)
	}
	if len(body) != taSize {
		return TA{}, fmt.Errorf("incorrect token size, got %d", len(body))
	}
	return *(*TA)(body), nil
}

// FPPrefix is the human-readable prefix for qconn fingerprints.
const FPPrefix = "qc"

const fpSize = 16

// FP is a certificate fingerprint (truncated BLAKE2b hash of the certificate's raw bytes).
// The fingerprint is encoded as bech32 with the "qc" prefix for human-readable representation.
type FP [fpSize]byte

// String returns the bech32-encoded fingerprint with "qc" prefix.
func (f FP) String() string {
	s, err := bech32.Encode(FPPrefix, f[:])
	if err != nil {
		panic("bech32 encode FP: " + err.Error())
	}
	return s
}

// IsZero returns true if the fingerprint is all zeros (unset).
func (f FP) IsZero() bool {
	return f == FP{}
}

// MarshalBinary implements encoding.BinaryMarshaler for efficient CBOR encoding.
func (f FP) MarshalBinary() ([]byte, error) {
	return f[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for CBOR decoding.
func (f *FP) UnmarshalBinary(data []byte) error {
	if len(data) != fpSize {
		return FingerprintSizeError{Got: len(data)}
	}
	copy(f[:], data)
	return nil
}

// FingerprintSizeError is returned when a fingerprint has an invalid byte length.
type FingerprintSizeError struct {
	Got int
}

func (e FingerprintSizeError) Error() string {
	return fmt.Sprintf("qconn: fingerprint must be %d bytes, got %d", fpSize, e.Got)
}

// FingerprintOf returns the fingerprint of a certificate.
func FingerprintOf(cert *x509.Certificate) FP {
	if cert == nil {
		return FP{}
	}
	return FingerprintHash(cert.Raw)
}

// FingerprintHash computes the fingerprint from raw certificate bytes.
func FingerprintHash(raw []byte) FP {
	h, err := blake2b.New(fpSize, nil)
	if err != nil {
		panic("blake2b.New: " + err.Error())
	}
	h.Write(raw)
	return *(*FP)(h.Sum(nil))
}

// ParseFP parses a fingerprint string in bech32 format (qc1...).
func ParseFP(s string) (FP, error) {
	var fp FP
	if s == "" {
		return fp, nil
	}

	hrp, data, err := bech32.Decode(s)
	if err != nil {
		return fp, fmt.Errorf("qconn: invalid fingerprint: %w", err)
	}
	if hrp != FPPrefix {
		return fp, fmt.Errorf("qconn: invalid fingerprint prefix: got %q, want %q", hrp, FPPrefix)
	}
	if len(data) != fpSize {
		return fp, FingerprintSizeError{Got: len(data)}
	}
	return *(*FP)(data), nil
}

// MustParseFP parses a bech32 fingerprint string, panicking on error.
func MustParseFP(s string) FP {
	fp, err := ParseFP(s)
	if err != nil {
		panic(err)
	}
	return fp
}

// MessageID uniquely identifies a request within a connection.
type MessageID uint64

// Action indicates the message type.
type Action uint8

const (
	ActionRequest  Action = 1
	ActionResponse Action = 2
	ActionAck      Action = 3 // Ack signals the request was received and to extend the timeout.
)

// ConnState represents the connection authorization state.
type ConnState uint8

const (
	StateProvisioning ConnState = 1
	StatePendingAuth  ConnState = 2
	StateConnected    ConnState = 3
)

func (s ConnState) String() string {
	names := map[ConnState]string{
		StateProvisioning: "provisioning",
		StatePendingAuth:  "pending-auth",
		StateConnected:    "connected",
	}
	if name, ok := names[s]; ok {
		return name
	}
	return "unknown"
}

// Message is the wire format for all communication.
type Message struct {
	ID      MessageID `cbor:"1,keyasint"`
	Action  Action    `cbor:"2,keyasint"`
	Target  Target    `cbor:"3,keyasint,omitempty"`
	From    Target    `cbor:"4,keyasint,omitempty"`
	Type    string    `cbor:"5,keyasint"`
	Payload []byte    `cbor:"6,keyasint,omitempty"`
	Error   string    `cbor:"7,keyasint,omitempty"`
	Role    string    `cbor:"8,keyasint,omitempty"`
}

// ProvisionRequest is sent by clients to request initial credentials.
// The client proves possession of the provisioning token by presenting
// a certificate signed by the derived CA (created from the token).
type ProvisionRequest struct {
	Hostname string `cbor:"hostname"`
	CSRPEM   []byte `cbor:"csr_pem"`
}

// ProvisionResponse contains the signed certificate.
type ProvisionResponse struct {
	CertPEM   []byte `cbor:"cert_pem"`
	RootCAPEM []byte `cbor:"root_ca_pem"`
}

// RenewRequest is sent by clients to renew their certificate.
type RenewRequest struct {
	CSRPEM []byte `cbor:"csr_pem"`
}

// RenewResponse contains the renewed certificate.
type RenewResponse struct {
	CertPEM []byte `cbor:"cert_pem"`
}

// ClientInfo describes a connected client.
type ClientInfo struct {
	Machine            string       `cbor:"machine"`
	Devices            []DeviceInfo `cbor:"devices,omitempty"`
	State              string       `cbor:"state"`
	MsgTypes           []string     `cbor:"msg_types,omitempty"`            // Message types the client advertises it can handle
	AuthorizedMsgTypes []string     `cbor:"authorized_msg_types,omitempty"` // Message types the client is authorized to handle
}

// RegisterDevicesRequest is sent by clients to register their devices.
type RegisterDevicesRequest struct {
	Devices []DeviceInfo `cbor:"devices"`
}

// AuthorizeClientRequest is sent by authorized clients to authorize another client by FP.
type AuthorizeClientRequest struct {
	FP       FP       `cbor:"fp"`
	MsgTypes []string `cbor:"msg_types,omitempty"` // Message types to authorize for this client
	Roles    []string `cbor:"roles,omitempty"`     // Roles to assign to this client
}

// SetClientRolesRequest is sent to update a client's roles.
type SetClientRolesRequest struct {
	FP    FP       `cbor:"fp"`
	Roles []string `cbor:"roles"`
}

// RevokeClientRequest is sent by authorized clients to revoke another client.
type RevokeClientRequest struct {
	FP FP `cbor:"fp"`
}

// SelfAuthorizeRequest is sent by pending-auth clients to authorize themselves.
type SelfAuthorizeRequest struct {
	Token string `cbor:"token"`
}

// StateChangeNotification is sent from server to client when the client's
// connection state changes. The client should close the current stream
// and open a new one after receiving this notification.
type StateChangeNotification struct {
	NewState  ConnState `cbor:"1,keyasint"`
	ExpiresAt time.Time `cbor:"2,keyasint,omitempty"`
}

// Common errors.
var (
	ErrNotConnected          = errors.New("target not connected")
	ErrInvalidState          = errors.New("invalid connection state")
	ErrUnknownType           = errors.New("unknown message type")
	ErrInvalidAction         = errors.New("invalid action")
	ErrNoCert                = errors.New("no certificate")
	ErrNoClientStore         = errors.New("no client store")
	ErrNoClientCert          = errors.New("no client certificate provided")
	ErrTimeout               = errors.New("request timeout")
	ErrInvalidToken          = errors.New("invalid provisioning token")
	ErrTokenTooShort         = errors.New("provisioning token must be at least 12 bytes")
	ErrInvalidAuthToken      = errors.New("invalid authorization token")
	ErrInvalidRequest        = errors.New("invalid request")
	ErrInvalidTarget         = errors.New("invalid target: must specify machine, device, or type")
	ErrDeviceRequiresMachine = errors.New("invalid target: device requires machine")
	ErrDeviceNotFound        = errors.New("device not found")
	ErrTypeNotFound          = errors.New("no device of requested type found")
	ErrClientRevoked         = errors.New("client revoked")
	ErrInvalidCertificate    = errors.New("invalid certificate")
	ErrDuplicateMachine      = errors.New("machine name already connected")
)
