# qconn & anex Design Document

`qconn` is a resilient, secure transport library built on top of QUIC. `anex` is the point-to-point multiplexer and management layer built upon `qconn`. Together, they provide a robust communication and orchestration layer for complex networked environments.

## Core Architecture

The system follows a tiered architecture, separating transport resiliency (`qconn`) from application-level routing and lifecycle management (`anex`).

### qconn - Transport Layer
- **Client**: A resilient connection supervisor that maintains a persistent QUIC connection, handling DNS re-resolution and connection migration.
- **Server**: Manages QUIC listeners for data and HTTP for provisioning.
- **CredentialStore**: Manages cryptographic identity and automatic certificate renewal.
- **AuthorizationManager**: Server-side gatekeeper controlling client access and issuing certificates.

### anex - Multiplex & Management Layer
- **Hub/Manager**: The central entry point for routing messages between clients.
- **Addressing**: Clients are addressed using a three-part tuple: `(Type, Machine, Device)`.
    - **Type**: Functional category (e.g., `printer`, `external-connect`).
    - **Machine**: Physical machine identifier (host).
    - **Device**: Specific hardware or service on a machine.
- **Point-to-Point Routing**: `anex` takes messages from submitters and forwards them to providers. It handles queuing and timeouts if the destination is temporarily unavailable.
- **Admin Function**: `anex` provides a unified interface for querying host states, provisioning new clients, and revoking access.

## Identity & Addressing

### Addressing Model
Each provider client is identified by:
1. **Type**: The class of service provided.
2. **Machine**: The physical host (guaranteed unique via certificate fingerprint).
3. **Devices**: A list of specific entities (hardware or services) hosted by that machine for a given type.

A client starting up identifies itself by `Machine` and `Type`, and periodically updates its list of `Devices`.

### State Management
Clients have a persistent **status** and a connection **state**:

**Status** (persisted in database):
- **Unauthenticated**: Has mTLS certificate but not authorized to communicate
- **Authenticated**: Authorized to communicate with other clients
- **Revoked**: Certificate has been revoked, connection rejected

**Connection State** (runtime only):
- **Provisioning**: Obtaining initial mTLS certificate
- **PendingAuth**: Connected but not yet authorized (status = Unauthenticated)
- **Connected**: Fully authorized and ready for communication (status = Authenticated)

### Hostname Uniqueness
Hostnames must be unique among active (authorized, non-expired) clients:
- When authorizing a client, the server validates that no other active client uses the same hostname
- This check is performed atomically with the authorization to prevent race conditions
- Messages are routed by hostname, so duplicates would cause routing ambiguity
- Once a client is revoked or its certificate expires, its hostname becomes available again
- The server returns `ErrDuplicateHostname` if authorization would create a duplicate

## Security & Certificate Lifecycle

### mTLS & Fingerprinting
Security is based on Mutual TLS (mTLS) over QUIC. Every machine has a unique certificate fingerprint used for persistent identification regardless of address changes.

### Provisioning Security
Provisioning tokens **only** grant the ability to obtain mTLS certificates:
- Provisioning clients can only call the provisioning endpoint
- After provisioning, clients have `StatusUnauthenticated` and `StatePendingAuth`
- **Provisioned clients cannot communicate** with other clients until authorized
- Authorization must be granted separately via:
  - **Auth token** (one-time bootstrap for initial admin setup)
  - **Admin authorization** (`admin/client/auth` endpoint)
- Authorization is granted per-fingerprint, never by hostname alone

### Auth Tokens vs Provisioning Tokens
- **Provisioning token**: Grants mTLS certificate issuance only. Does not grant communication.
- **Auth token**: One-time use. Grants temporary authorization for bootstrap scenarios (e.g., first admin client). Created by server on first startup or via `CreateAuthToken()`.

After the first admin client is authorized via auth token, all subsequent clients should be authorized via the `admin/client/auth` endpoint.

### Certificate Flow (CSR-Based)
Private keys never leave the client:
1. Client generates keypair locally
2. Client sends Certificate Signing Request (CSR) to server
3. Server validates and signs, returns certificate only
4. Client stores certificate with its locally-generated key

### Role Management
Roles are managed **server-side only**:
- Client certificates contain identity (hostname, fingerprint) but not roles
- Roles are assigned via `Hub.staticAuthorizations` keyed by fingerprint
- Role lookups use fingerprint only; hostname fallback is not permitted
- The hub is the trusted authority for role assignment

### Requested vs Authorized Roles
Clients can advertise which roles they want via `ClientOpt.DefaultRoles`:
- **Requested roles** (`ClientRecord.RequestedRoles`): What the client advertises it wants
- **Authorized roles** (`ClientRecord.Roles`): What the admin has granted
- The two sets do not need to overlap - admin may grant different roles than requested
- Clients include `RequestedRoles` in `update-client-info` for admin visibility
- Admins explicitly set authorized roles via `admin/client/auth` or `admin/client/set-roles`

### Automated Renewal
To minimize the exposure of revoked status, certificates have a short validity period:
- **Default Validity**: 45 days (configurable).
- **Renewal Window**: Automatic renewal starts when 15 days remain (configurable).
- **Rate Limiting**: Renewals are rate-limited to prevent abuse.
- **Interface**: The `Renew` function is automatically invoked by clients to obtain fresh credentials.

### Garbage Collection
Once a certificate's end date has passed, any associated revocation status can be safely dropped from the system's tracking lists.

## Routing & Roles

### Authorization Model
All message routing is subject to role-based authorization:
- **SendsTo**: Roles define which job types a client can submit messages to
- **Provides**: Roles define which job types a client can receive/handle
- **No Self-Send Bypass**: Even messages to self require proper role authorization

### Admin Endpoints
Admin functions use role-based authorization with different access levels:
- **`list-machines`**: Query endpoint, accessible to roles that need discovery (e.g., for broadcast)
- **`provision`**: Administrative action, restricted to admin roles only
- Both use `canSend` checks against their respective job types
- Unauthorized calls are rejected with role error

### Message Flow
1. **Submit**: A submitter sends a message to a `(Type, Machine, Device)`.
2. **Route**: `anex` determines the target machine's current connection.
3. **Wait/Error**: If the target is unavailable, `anex` waits for a configurable period before returning an error to the submitter.
4. **Respond**: If the target is available, the message is delivered, and the response (or error) is returned to the submitter.

## Message Protocol

### Message Actions
Messages carry an `Action` field (`MessageAction int8`) that indicates their purpose:
- **Deliver** (0): Normal message delivery from client to server for routing
- **Ack** (1): Acknowledgment from target client that message was received
- **StatusUpdate** (2): Progress notification from server to sender during routing

Clients may only send messages with `Action=Deliver` to the server. The server validates this and closes streams from misbehaving clients that send Ack or StatusUpdate actions. Ack messages flow from target to server (during forwarding), and StatusUpdate messages flow from server to sender.

### Message State Tracking
Each message progresses through a linear state machine (`MessageState int8`):
1. **Unsent**: Message created but not yet sent
2. **Sent**: Message sent by client to server
3. **ServerReceived**: Server received the message
4. **ResolvedMachine**: Server found the target machine
5. **ResolvedDevice**: Server found the target device (if specified)
6. **SentToTarget**: Server sent message to target client
7. **TargetAck**: Target client acknowledged receipt
8. **TargetResponse**: Target client sent response
9. **ForwardedResponse**: Server forwarded response to sender
10. **ClientReceived**: Sender client received the response

The server sends status updates to the sender as the message progresses, enabling real-time visibility into routing progress.

### Dual Timeout System
Message routing uses two distinct timeouts:
- **Resolution Timeout**: Time allowed to find the target machine and receive an acknowledgment. Applies during states 1-6.
- **Job Timeout**: Time allowed for the target to process and respond after acknowledging. Applies during states 7-8.

When the target client receives a message, it immediately sends an Ack back to the server. This signals that the job has been accepted and extends the deadline from the resolution timeout to the job timeout. This prevents slow handler execution from being mistaken for routing failures.

### MessageObserver Interface
The server accepts a `MessageObserver` for monitoring message lifecycle:
```go
type MessageObserver interface {
    OnMessageComplete(src Identity, dest Addr, msgID MessageID, lastState MessageState, duration time.Duration, err error)
}
```
This enables metrics collection, logging, and debugging of message routing performance.
