# qconn Behavior Documentation

This document describes all production behaviors of the qconn package, including edge cases, error conditions, and security considerations.

## Overview

qconn is a QUIC-based secure messaging system with:
- Mutual TLS authentication using X.509 certificates
- Certificate provisioning via shared secrets
- Role-Based Access Control (RBAC)
- Client-to-client message routing
- Device-based routing (by name or type)

## Connection Lifecycle

### Connection States

| State | Value | Description |
|-------|-------|-------------|
| `StateProvisioning` | 1 | Client is requesting initial credentials |
| `StatePendingAuth` | 2 | Client has credentials but not authorized |
| `StateConnected` | 3 | Client is fully authorized |

### Client Status (Persistent)

| Status | Value | Description |
|--------|-------|-------------|
| `StatusUnknown` | 0 | Client not in store or expired |
| `StatusUnauthenticated` | 1 | Provisioned but not authorized |
| `StatusAuthenticated` | 2 | Authorized to connect |
| `StatusRevoked` | 3 | Certificate revoked |

### State Transitions

```
┌─────────────────┐
│  New Connection │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Is provisioning cert?                                        │
│   YES → StateProvisioning → provision-csr → disconnect      │
│   NO  → Check GetClientStatus(fp)                           │
│         StatusRevoked → close with error                    │
│         StatusAuthenticated → StateConnected                │
│         Otherwise → StatePendingAuth                        │
└─────────────────────────────────────────────────────────────┘
```

**Tested:** `TestBoltAuthManagerFullProvisioning`, `TestSelfAuthorization`, `TestAuthorizeClient`, `TestRevokedClientRejected`

## Provisioning Flow

### How It Works

1. Client generates a deterministic CA from the shared provisioning token
2. Client creates a short-lived leaf certificate signed by that CA
3. Client connects with this provisioning certificate
4. Server verifies the certificate against its own derived CA pool
5. Client sends `provision-csr` with hostname and CSR
6. Server signs CSR with the real CA, returns cert + root CA PEM
7. Client saves credentials and reconnects with real certificate
8. **Client remains unauthorized** - cannot communicate with other clients yet

### What Provisioning Grants

Provisioning tokens **only** grant the ability to obtain mTLS certificates. After provisioning:
- Client has valid credentials for mutual TLS authentication
- Client status is `StatusUnauthenticated`
- Client state is `StatePendingAuth`
- Client **cannot** send messages to other clients
- Client **cannot** call admin endpoints
- Client **can** call `update-client-info` and `self-authorize`

To gain communication privileges, the client must be **authorized** (see Authorization Methods below).

### Behaviors

| Scenario | Behavior | Tested |
|----------|----------|--------|
| Valid provisioning token | Server accepts, signs CSR, returns cert with `StatusUnauthenticated` | `TestBoltAuthManagerFullProvisioning` |
| Invalid provisioning token | TLS handshake fails (cert not in pool) | - |
| CSR hostname mismatch | Server returns error | - |
| Provisioning client sends other messages | Server returns "unknown message type" | - |
| Client already provisioned | `NeedsProvisioning()` returns false, skips provisioning | `TestBoltAuthManagerFullProvisioning` |

### Security Considerations

- Provisioning tokens should be rotated after initial deployment
- **Tokens grant only mTLS certificate issuance - not authorization or communication**
- Each token creates an independent CA for isolation
- Token-derived certificates are short-lived (1 hour)
- A compromised provisioning token cannot be used to communicate with existing clients

## Authorization Methods

Authorization grants a client the ability to:
- Send messages to other clients (subject to RBAC if configured)
- Call admin endpoints (subject to RBAC if configured)
- Receive messages from other clients

Without authorization, a provisioned client can only call `update-client-info` and `self-authorize`.

### Method 1: Self-Authorization with Auth Token

Auth tokens provide **one-time bootstrap authorization** for newly provisioned clients. This is typically used during initial server setup when no admin client exists yet.

1. Server creates an auth token on first startup (printed to console)
2. Admin creates additional tokens via `auth.CreateAuthToken()`
3. Token is valid for 24 hours (redemption window)
4. Client calls `self-authorize` with the token
5. Server validates and redeems token (**one-time use only**)
6. Client gets temporary authorization (24 hours)
7. State changes to `StateConnected`

**Important:** Auth tokens are for **bootstrap only**. After the first admin client is authorized, use admin authorization for all subsequent clients.

| Scenario | Behavior | Tested |
|----------|----------|--------|
| Valid token, first use | Authorization succeeds, state → Connected | `TestSelfAuthorization` |
| Token already redeemed | Returns `invalid authorization token` | - |
| Token expired (>24h old) | Returns `invalid authorization token` | - |
| Invalid token format | Returns error | `TestSelfAuthorization` |

**Tested:** `TestSelfAuthorization`, `TestAuthRBAC/Admin_TempAuth_Allow`

### Method 2: Admin Authorization

This is the standard method for authorizing clients after the initial admin is set up.

1. Admin client calls `admin/client/auth` with target FP, roles, and message types
2. Server sets target status to `StatusAuthenticated`
3. Server assigns roles (for RBAC-controlled communication)
4. Server sets target state to `StateConnected` (if connected)
5. Server sends `state-change` notification to target (if connected)

The admin can authorize clients that are online or offline. Offline clients will have their authorization stored and will be in `StateConnected` when they next connect.

| Scenario | Behavior | Tested |
|----------|----------|--------|
| Target connected | Authorization succeeds, notification sent | `TestAuthorizeClient` |
| Target not connected | Authorization succeeds, stored for later | `TestIntegration` |
| Admin not authorized | Returns `request not allowed` | `TestAuthRBAC/Admin_NoRBAC_NoTempAuth_Deny` |

**Tested:** `TestAuthorizeClient`, `TestAuthRBAC/C2C_NoRBAC_Allow`

### Authorization vs RBAC

- **Authorization** determines whether a client can communicate at all
- **RBAC** (Role-Based Access Control) determines **which** message types a client can send/receive

Without RBAC configured, authorized clients can send any message type to any other authorized client.

With RBAC configured:
- Clients must include a role claim in each request
- The role must be assigned to the client
- The role must have `Submit` permission for the message type
- The target must have a role with `Provide` permission for the message type

## System Messages

### Available by State

| State | Available Messages |
|-------|-------------------|
| `StateProvisioning` | `provision-csr` |
| `StatePendingAuth` | `self-authorize`, `update-client-info` |
| `StateConnected` | `renew`, `update-client-info`, `register-devices`, `self-authorize`, `admin/*` |

### Message Behaviors

#### `provision-csr`
- **Input:** `ProvisionRequest{Hostname, CSRPEM}`
- **Output:** `ProvisionResponse{CertPEM, RootCAPEM}`
- **Behavior:** Signs CSR with server CA, creates client record with `StatusUnauthenticated`
- **Note:** Client must be authorized separately before it can communicate with other clients

#### `self-authorize`
- **Input:** `SelfAuthorizeRequest{Token}`
- **Output:** `StateChangeNotification{NewState, ExpiresAt}`
- **Behavior:** Validates token, grants temp auth, changes state to Connected

#### `update-client-info`
- **Input:** `ClientInfoUpdate{MachineIP, Devices, MsgTypes}`
- **Output:** None
- **Behavior:** Updates client record, updates device routing tables
- **Note:** Server sets `RemoteIP` from connection address

**Tested:** `TestUpdateClientInfo`

#### `register-devices`
- **Input:** `RegisterDevicesRequest{Devices}`
- **Output:** None
- **Behavior:** Replaces client's device list, updates type routing index

#### `renew`
- **Input:** `RenewRequest{CSRPEM}`
- **Output:** `RenewResponse{CertPEM}`
- **Behavior:** Signs new CSR, preserves roles and client info under new FP
- **Note:** Client must reconnect with new certificate after saving

**Tested:** `TestRenewalWithFakeTime`

#### `admin/client/list`
- **Input:** None
- **Output:** `[]ClientInfo`
- **Requires:** Temp auth OR RBAC permission

**Tested:** `TestServerClientBasic`, `TestAuthRBAC/Admin_TempAuth_Allow`

#### `admin/client/auth`
- **Input:** `AuthorizeClientRequest{FP, MsgTypes, Roles}`
- **Output:** None
- **Behavior:** Authorizes client, optionally assigns roles, sends state-change notification
- **Requires:** Temp auth OR RBAC permission

**Tested:** `TestAuthorizeClient`, `TestAuthRBAC/C2C_NoRBAC_Allow`

#### `admin/client/set-roles`
- **Input:** `SetClientRolesRequest{FP, Roles}`
- **Output:** None
- **Requires:** Temp auth OR RBAC permission

## Client-to-Client Routing

### Target Resolution

| Target Type | Resolution |
|-------------|------------|
| `Target{Machine: "hostname"}` | Lookup in machines map by hostname |
| `Target{Machine: "host", Device: "dev"}` | Lookup machine, verify device exists |
| `Target{DeviceType: "type"}` | Find first client with device of that type |

### Routing Behaviors

| Scenario | Behavior | Tested |
|----------|----------|--------|
| Target found, sender StateConnected | Route request | `TestClientToClientRouting` |
| Sender not StateConnected | Returns `invalid connection state` | `TestAuthorizeClient` |
| Target machine not found | Returns `target not connected` | `TestAuthRBAC/C2C_NoRBAC_TargetNotConnected_Deny` |
| Target device not found | Returns `device not found` | `TestDeviceTypeRouting` |
| Target device type not found | Returns `no device of requested type found` | `TestDeviceTypeRouting` |
| Device type routing | Routes to first matching device | `TestDeviceTypeRouting` |
| Specific device routing | Routes to named device on machine | `TestDeviceTypeRouting` |
| RBAC denies request | Returns `request not allowed` | `TestAuthRBAC/C2C_RBAC_*` |

### Request/Response Flow

```
Client A                    Server                      Client B
    │                          │                           │
    │─── Request (ID=1) ──────►│                           │
    │                          │─── Request (ID=42) ──────►│
    │                          │                           │
    │                          │◄── Ack (ID=42) ──────────│ (optional)
    │◄── Ack (ID=1) ──────────│                           │
    │                          │                           │
    │                          │◄── Response (ID=42) ─────│
    │◄── Response (ID=1) ─────│                           │
```

### Acknowledgments (Ack)

- Target handler can call `ack(ctx)` to signal long-running operation
- Ack extends the route timeout by `RequestTimeout` (default 30s)
- Multiple Acks can be sent to keep extending the timeout
- Without Ack, request times out after `RequestTimeout`

| Scenario | Behavior | Tested |
|----------|----------|--------|
| Handler completes within timeout | Response returned | `TestClientToClientRouting` |
| Handler exceeds timeout without Ack | Returns `request timeout` | `TestSlowHandler/WithoutAckTimesOut` |
| Handler sends Ack, then completes | Response returned | `TestSlowHandler/WithAckSucceeds` |
| Origin disconnects before response | Response silently dropped | - |

**Tested:** `TestSlowHandler`

## Role-Based Access Control (RBAC)

### Configuration

```go
Roles: map[string]*RoleConfig{
    "controller": {
        Submit:  []string{"print", "scan"},  // Can send these message types
        Provide: []string{},                  // Cannot handle any
    },
    "printer": {
        Submit:  []string{},                  // Cannot send
        Provide: []string{"print", "scan"},   // Can handle these
    },
}
```

### Authorization Logic

#### System Messages (target = $system)

1. **Non-admin messages** (not prefixed with `admin/`): Always allowed
2. **Admin messages**:
   - If client has temp auth (from `self-authorize`): **Allow**
   - If RBAC is configured:
     - Check client has claimed role assigned
     - Check role can Submit the msgType
     - If both pass: **Allow**
   - Otherwise: **Deny**

#### Client-to-Client Messages

1. If no RBAC configured: **Allow all** (after state check)
2. If RBAC configured:
   - Role claim is **required**
   - Originator must have the claimed role assigned
   - Claimed role must have Submit permission for msgType
   - Target must have some role with Provide permission for msgType
   - All checks pass: **Allow**

### RBAC Test Coverage

| Scenario | Tested |
|----------|--------|
| Non-admin system message, provisioned client | `TestAuthRBAC/NonAdmin_System_Provisioned_Allow` |
| Non-admin system message, self-auth client | `TestAuthRBAC/NonAdmin_System_SelfAuth_Allow` |
| Admin message, no RBAC, no temp auth | `TestAuthRBAC/Admin_NoRBAC_NoTempAuth_Deny` |
| Admin message, with temp auth | `TestAuthRBAC/Admin_TempAuth_Allow` |
| Admin message, RBAC with valid role | `TestAuthRBAC/Admin_RBAC_WithRole_Allow` |
| Admin message, RBAC with wrong role | `TestAuthRBAC/Admin_RBAC_WrongRole_Deny` |
| Admin message, RBAC role not assigned | `TestAuthRBAC/Admin_RBAC_NoRoleAssigned_Deny` |
| Admin message, RBAC empty role claim | `TestAuthRBAC/Admin_RBAC_EmptyRole_Deny` |
| C2C, no RBAC | `TestAuthRBAC/C2C_NoRBAC_Allow` |
| C2C, target not connected | `TestAuthRBAC/C2C_NoRBAC_TargetNotConnected_Deny` |
| C2C, RBAC valid roles | `TestAuthRBAC/C2C_RBAC_ValidRoles_Allow` |
| C2C, RBAC role can't submit | `TestAuthRBAC/C2C_RBAC_RoleCantSubmit_Deny` |
| C2C, RBAC target can't provide | `TestAuthRBAC/C2C_RBAC_TargetCantProvide_Deny` |
| C2C, RBAC originator no role | `TestAuthRBAC/C2C_RBAC_OriginatorNoRole_Deny` |
| C2C, RBAC empty role claim | `TestAuthRBAC/C2C_RBAC_EmptyRole_Deny` |
| C2C, target has multiple roles | `TestAuthRBAC/C2C_RBAC_MultiRole_TargetHasMultiple_Allow` |
| C2C, bidirectional peer roles | `TestAuthRBAC/C2C_RBAC_Bidirectional_Allow` |

## Certificate Renewal

### Flow

1. Client creates new CSR (new key pair)
2. Client calls `renew` with CSR
3. Server signs CSR, returns new certificate
4. Server copies roles and client info to new FP
5. Client saves new credentials
6. Client reconnects with new certificate

### Behaviors

| Scenario | Behavior | Tested |
|----------|----------|--------|
| Valid renewal request | New cert returned, roles preserved | `TestRenewalWithFakeTime` |
| Client is revoked | Returns `client revoked` | - |
| CSR hostname mismatch | Returns error (CSR validation) | - |

### Data Preserved After Renewal

- `Roles` (RBAC roles)
- `AuthorizedMsgTypes`
- `MachineIP`, `RemoteIP`
- `Devices`
- `Status` (maintained)

**Tested:** `TestRenewalWithFakeTime`

## Cleanup and Expiration

### Automatic Cleanup

- `StartCleanup(interval)` starts background goroutine
- `CleanupExpired()` removes expired records from:
  - Client records (cert expiry)
  - Auth tokens (24h redemption window)
  - Temp auth records (24h after redemption)

### Expiration Behaviors

| Item | Expiration | Effect |
|------|------------|--------|
| Client record | Cert NotAfter | `GetClientStatus` returns `StatusUnknown` |
| Auth token | 24h after creation | Token invalid for redemption |
| Temp auth | 24h after redemption | Temp auth check fails |

**Tested:** `TestBoltAuthManagerCleanup`, `TestRenewalWithFakeTime`

## Error Conditions

### Standard Errors

| Error | Condition |
|-------|-----------|
| `ErrNotConnected` | Target machine not in connection map |
| `ErrInvalidState` | Operation not allowed in current state |
| `ErrUnknownType` | Message type not in handler map |
| `ErrInvalidAction` | Action not Request/Response/Ack |
| `ErrNoCert` | No certificate provided |
| `ErrNoClientCert` | Client didn't present certificate |
| `ErrTimeout` | Request exceeded timeout without response |
| `ErrInvalidToken` | Invalid provisioning token |
| `ErrInvalidAuthToken` | Invalid/expired/redeemed auth token |
| `ErrInvalidRequest` | Malformed request payload |
| `ErrInvalidTarget` | Target missing machine/device/type |
| `ErrDeviceRequiresMachine` | Device specified without machine |
| `ErrDeviceNotFound` | Specified device not registered |
| `ErrTypeNotFound` | No device of requested type |
| `ErrClientRevoked` | Client certificate was revoked |
| `ErrInvalidCertificate` | Certificate parsing failed |

### Error Propagation

- Handler errors are returned in `Message.Error` field
- Client receives them as `*RequestError` from `Request()`
- System errors close the connection

## Message Size Limits

### Overview

The server enforces different message size limits based on connection state to protect against denial-of-service attacks:

- **Unauthenticated clients** (provisioning or pending auth): 10 KB default
- **Authenticated clients** (connected): 10 MB default

These limits are configurable via `ServerOpt.UnauthenticatedMaxMsgSize` and `ServerOpt.AuthenticatedMaxMsgSize`.

### Behavior

| State | Max Message Size | Exceeded Behavior |
|-------|------------------|-------------------|
| `StateProvisioning` | 10 KB | Connection closed, `ErrMessageTooLarge` |
| `StatePendingAuth` | 10 KB | Connection closed, `ErrMessageTooLarge` |
| `StateConnected` | 10 MB | Connection closed, `ErrMessageTooLarge` |

When a client's state changes from `StatePendingAuth` to `StateConnected` (via self-authorize or admin authorization), the message size limit is automatically upgraded.

### Security Considerations

- Lower limits for unauthenticated clients prevent resource exhaustion attacks
- Provisioning messages are small (CSR + hostname) and fit within 10 KB
- Authenticated clients may need to send larger payloads (device lists, etc.)
- The limit applies per-message, not per-connection

**Tested:** `TestMessageSizeLimits`

## DNS Resolver

### Overview

Clients can use a custom DNS resolver to resolve server hostnames. This enables:

- Custom DNS server configuration
- Service discovery integration
- Failover to different server addresses

### Configuration

```go
client, err := NewClient(ctx, ClientOpt{
    ServerAddr: "myserver.local",     // Hostname to resolve
    Auth:       creds,
    Resolver:   &DNSResolver{
        Nameserver: "8.8.8.8:53",     // Custom DNS server
        Port:       "4433",            // Port to append to resolved IP
    },
})
```

### Behavior

| Scenario | Behavior | Tested |
|----------|----------|--------|
| Resolver set, hostname resolves | Connect to resolved address | `TestDNSResolverChanges/ResolverCalledOnReconnect` |
| Resolver set, provisioning | Resolve before initial connect AND after provisioning | `TestDNSResolverChanges/ResolverCalledDuringProvisioning` |
| DNS changes between connections | New connection uses new address | `TestDNSResolverChanges/ResolverAddressChanges` |
| Resolver not set | Use ServerAddr directly | (default behavior) |
| Resolution fails | Return error from NewClient | - |

### Provisioning with Resolver

During provisioning, the resolver is called twice:
1. Before initial connection (for provisioning)
2. After provisioning completes (before reconnecting with new credentials)

This allows the server address to change during the provisioning flow if needed.

**Tested:** `TestDNSResolverChanges`

## Concurrency Model

### Server-Side

- One goroutine per client connection (read loop)
- Shared connection maps protected by `sync.RWMutex`
- Route table protected by separate `sync.Mutex`
- CBOR encoding protected by per-connection `sendMu`

### Client-Side

- One goroutine for read loop
- Pending requests tracked in map with mutex
- Encoding protected by `sendMu`
- Channel-based response delivery

### Thread Safety

| Operation | Synchronization |
|-----------|-----------------|
| Connection registration | `Server.mu` (write lock) |
| Target resolution | `Server.mu` (read lock) |
| Route creation/lookup | `Server.routeMu` |
| Message encoding | `clientConn.sendMu` |
| Pending request tracking | `Client.pendingMu` |
| Message size limit changes | `limitedReader.mu` |
| Fake time (testing) | `timeMu` |

## Configuration Options

### ServerOpt

| Field | Default | Description |
|-------|---------|-------------|
| `Auth` | required | AuthManager implementation |
| `Clients` | required | ClientStore implementation |
| `RequestTimeout` | 30s | Per-request timeout |
| `KeepalivePeriod` | 45s | QUIC keepalive interval |
| `UnauthenticatedMaxMsgSize` | 10 KB | Max message size for provisioning/unauthenticated clients |
| `AuthenticatedMaxMsgSize` | 10 MB | Max message size for authenticated clients |

### ClientOpt

| Field | Default | Description |
|-------|---------|-------------|
| `ServerAddr` | required | Server address (or hostname if Resolver set) |
| `Auth` | required | CredentialStore implementation |
| `Handler` | nil | Handler for incoming requests |
| `Resolver` | nil | DNS resolver for hostname lookup |
| `KeepalivePeriod` | 45s | QUIC keepalive interval |

### BoltAuthConfig

| Field | Default | Description |
|-------|---------|-------------|
| `DBPath` | "auth.db" | Path to bbolt database |
| `ServerHostname` | os.Hostname() | Server certificate CN |
| `ProvisionTokens` | nil | List of valid provisioning tokens |
| `CACert`/`CAKey` | generated | Inject existing CA (optional) |
| `Roles` | nil | RBAC role configuration |

## Production Checklist

### Security

- [ ] Rotate provisioning tokens after initial deployment
- [ ] Use strong random provisioning tokens (minimum 32 bytes)
- [ ] Store auth tokens securely (they grant admin access)
- [ ] Enable RBAC for multi-tenant deployments
- [ ] Monitor certificate expiration
- [ ] Run `CleanupExpired()` periodically

### Reliability

- [ ] Set appropriate `RequestTimeout` for workloads
- [ ] Use `Ack` in handlers for long-running operations
- [ ] Handle `state-change` notifications in clients
- [ ] Implement certificate renewal before expiry
- [ ] Configure appropriate QUIC keepalive for NAT traversal

### Monitoring

- [ ] Track `admin/client/list` for connected clients
- [ ] Monitor provisioning success/failure rates
- [ ] Alert on certificate expiration (45-day default validity)
- [ ] Log authorization failures for security auditing

## Test Coverage Summary

| Category | Tests |
|----------|-------|
| Basic connectivity | `TestServerClientBasic` |
| Client-to-client routing | `TestClientToClientRouting` |
| Full provisioning flow | `TestBoltAuthManagerFullProvisioning` |
| Self-authorization | `TestSelfAuthorization` |
| Admin authorization | `TestAuthorizeClient` |
| RBAC (18 scenarios) | `TestAuthRBAC/*` |
| Request timeouts & Ack | `TestSlowHandler` |
| Certificate renewal | `TestRenewalWithFakeTime` |
| Record cleanup | `TestBoltAuthManagerCleanup` |
| Client info updates | `TestUpdateClientInfo` |
| Device-type routing | `TestDeviceTypeRouting` |
| Revoked client rejection | `TestRevokedClientRejected` |
| Message size limits | `TestMessageSizeLimits/*` |
| DNS resolver behavior | `TestDNSResolverChanges/*` |

## Untested Edge Cases

The following scenarios are not explicitly tested but are implemented:

1. Multiple provisioning tokens (isolation)
2. Connection closed during request
3. CSR hostname validation failure
4. Concurrent client registration race conditions
5. Route timeout with multiple Acks
6. QUIC stream errors
7. Database corruption recovery
8. DNS resolution failures
