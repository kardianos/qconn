# qconn

A hub-spoke secure transport for real-time messages over QUIC with mTLS authentication.

## Architecture

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Client  │────▶│ Server  │◀────│ Client  │
└─────────┘     └─────────┘     └─────────┘
     │               │               │
     └───────────────┴───────────────┘
           All traffic encrypted
           via mTLS over QUIC
```

Clients connect to a central server which handles authentication, authorization, and message routing. Clients identify themselves via certificate fingerprints.

### Addressing

Messages use a three-part tuple: `(ServiceType, Machine, Device)`
- **ServiceType**: Category of work (e.g., "print", "scan")
- **Machine**: Host identified by certificate fingerprint or hostname
- **Device**: Specific hardware/service instance on that machine

## Provisioning & Authorization

Provisioning and authorization are **separate steps**:

1. **Provisioning** - Client obtains mTLS certificate using a shared token
   - Client generates keypair locally (private key never leaves client)
   - Client sends CSR to server, receives signed certificate
   - Client can now connect but **cannot communicate** with other clients

2. **Authorization** - Admin grants communication privileges
   - Via auth token (one-time bootstrap for first admin)
   - Via `admin/client/auth` endpoint (standard method)

This two-step process ensures compromised provisioning tokens cannot be used to communicate with existing clients.

### Connection States

| State | Description |
|-------|-------------|
| `StateProvisioning` | Requesting initial credentials |
| `StatePendingAuth` | Has credentials, awaiting authorization |
| `StateConnected` | Fully authorized |

### Client Status (Persistent)

| Status | Description |
|--------|-------------|
| `StatusUnauthenticated` | Provisioned but not authorized |
| `StatusAuthenticated` | Authorized to connect |
| `StatusRevoked` | Certificate revoked |

## Role-Based Access Control

Roles define message permissions:

```go
Roles: map[string]*RoleConfig{
    "controller": {
        Submit:  []string{"print", "scan"},  // Can send these types
        Provide: []string{},                  // Cannot handle any
    },
    "printer": {
        Submit:  []string{},                  // Cannot send
        Provide: []string{"print", "scan"},   // Can handle these
    },
}
```

- Roles are managed server-side only (not embedded in certificates)
- Without RBAC configured, authorized clients can communicate freely
- With RBAC, every message requires matching Submit/Provide permissions

## Certificate Lifecycle

- **Validity**: 45 days default
- **Renewal**: Automatic when 15 days remain
- **Expiration cleanup**: Expired records can be safely removed
- **Expired certificates**: Client automatically re-provisions (new fingerprint, requires admin re-approval)

Hostnames must be unique among active clients. When a client is revoked or expires, its hostname becomes available for reuse.

### Disconnected Client Recovery

If a client is offline long enough for its certificate to expire:

1. Client detects expired certificate on reconnect
2. Client automatically re-provisions using the original provisioning token
3. Client receives a **new certificate with new fingerprint**
4. Admin re-authorizes with `qconn admin approve -fp <newFP>`

No manual intervention is needed on the client machine.

## Message Protocol

Messages progress through states with status updates sent to the sender:

```
Client A → Server → Client B
    │         │         │
    │── Req ─▶│── Req ─▶│
    │         │◀── Ack ─│
    │◀─ Ack ──│         │
    │         │◀─ Resp ─│
    │◀─ Resp ─│         │
```

**Dual timeout system:**
- **Resolution timeout**: Find target and receive acknowledgment
- **Job timeout**: Target processes request after acknowledging

Target handlers can call `ack(ctx)` to signal long-running operations and extend the timeout.

## qstore Package

Config file storage with platform-specific encryption.

### DataStore Interface

```go
type DataStore interface {
    Get(key string, decrypt bool) ([]byte, error)
    Set(key string, encrypt bool, value []byte) error
    Path() string
}
```

### Config File Format

```
# Text values use T{...}
server=T{localhost:9443}
cert=T{
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
}

# Binary values use B{...} with base64
key=B{SGVsbG8gV29ybGQ=}
```

- Text encoding: printable ASCII without braces `{}`
- Binary encoding: base64, line-wrapped at 60 chars for long values

### Encryption

- **Linux**: nacl/secretbox with embedded key
- **Windows**: DPAPI

### Default Paths

| Platform | Admin | Service |
|----------|-------|---------|
| Linux | `~/.config/qconn/admin` | `/etc/qconn/client` |
| Windows | `CU\SOFTWARE\qconn\admin` | `LM\SOFTWARE\qconn\client` |
