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
Clients can be in one of three statuses:
- **Unprovisioned**: Authenticated via token but lacking long-term credentials.
- **Provisioned-Online**: Connected and ready for communication.
- **Provisioned-Offline**: Authorized but currently disconnected.

## Security & Certificate Lifecycle

### mTLS & Fingerprinting
Security is based on Mutual TLS (mTLS) over QUIC. Every machine has a unique certificate fingerprint used for persistent identification regardless of address changes.

### Provisioning Security
Provisioning tokens allow initial system connection but grant **no operational access**:
- Provisioning clients can only call the provisioning endpoint
- All other service calls are blocked at the transport layer
- After provisioning, clients idle until authorized by an administrator
- Authorization is granted per-fingerprint, never by hostname alone

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
