package qdef

import (
	"net/netip"
	"time"
)

// ProvisionReq parameters for provision-machine RPC.
// Identifier can be either a hostname (for unprovisioned machines) or
// a fingerprint string (for already-provisioned machines being re-authorized).
type ProvisionReq struct {
	Identifier []string `cbor:"fingerprint"`
}

// ListClientsReq parameters for the list-clients RPC.
type ListClientsReq struct {
	Fingerprint      []FP `cbor:"fingerprint"`       // Optional filter to limit to given fingerprints.
	ShowUnauthorized bool `cbor:"show_unauthorized"` // If false, only show authorized clients.
	IncludeDevices   bool `cbor:"include_device"`
	IncludeExternal  bool `cbor:"include_external"` // If true, include external targets from MessageRouter.
}

// ClientInfo represents a provisioned client with authorization details.
// All clients in this list have been provisioned (have certificates).
type ClientInfo struct {
	Fingerprint    FP             `cbor:"fingerprint"`
	ExternalID     string         `cbor:"extid"`
	Hostname       string         `cbor:"hostname"`
	LocalAddr      netip.Addr     `cbor:"local_addr"`
	Status         ClientStatus   `cbor:"status"`
	Authorized     bool           `cbor:"authorized"` // True if Status == StatusAuthorized.
	Online         bool           `cbor:"online"`
	CreatedAt      time.Time      `cbor:"created_at"`
	ExpiresAt      time.Time      `cbor:"expires_at"`
	LastAddr       netip.AddrPort `cbor:"last_addr"`
	Roles          []string       `cbor:"roles"`           // Authorized roles (from static authorization).
	RequestedRoles []string       `cbor:"requested_roles"` // Roles the client requested during provisioning.
	LastSeen       time.Time      `cbor:"last_seen"`       // When the client was last seen (connected/disconnected).
	Devices        []DeviceInfo   `cbor:"devices"`
}

// ListClientsResp response from list-clients RPC.
type ListClientsResp struct {
	Clients []ClientInfo `cbor:"clients"`
}

// AuthorizeReq parameters for the authorize-client RPC.
// Authorization approves the client's requested roles; it does not set new roles.
type AuthorizeReq struct {
	Fingerprint FP `cbor:"fingerprint"`
}

// RevokeReq parameters for the revoke-client RPC.
type RevokeReq struct {
	Fingerprint FP `cbor:"fingerprint"`
}
