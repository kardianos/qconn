# qconn Design Document

`qconn` is a resilient, secure transport library built on top of QUIC. It provides a robust communication layer designed for environments with flaky network conditions, dynamic IP addresses, and high security requirements.

## Core Architecture

The library follows a modular design, separating transport logic from identity management and authorization.

### Components

- **Client**: A resilient connection supervisor that maintains a persistent QUIC connection. It handles DNS re-resolution and connection migration automatically.
- **Server**: A multi-protocol server that manages a QUIC listener for data transport and an HTTP listener for client provisioning.
- **CredentialStore**: Abstracts the storage and retrieval of the client's cryptographic identity (certificates and keys).
- **AuthorizationManager**: A gatekeeper on the server that controls which clients are allowed to communicate based on their certificate's Common Name (CN).
- **StreamHandler**: The application-level entry point for handling incoming QUIC streams.

## Resiliency Model

`qconn` is built for "always-on" connectivity.

### Connection Supervisor
The `Client` runs a background supervisor that:
1. **DNS Monitoring**: Periodically re-resolves the server's hostname. If the address changes, it triggers a reconnection attempt.
2. **Automatic Reconnect**: If the QUIC connection is lost, the supervisor enters a backoff retry loop to restore connectivity.
3. **Session Resumption**: Leveraging QUIC's 0-RTT and connection migration features where applicable to minimize downtime.

## Security Model

Security is baked into the transport layer using Mutual TLS (mTLS) over QUIC.

### Mutual TLS (mTLS)
- **Identity**: Every client and server must have a certificate signed by a trusted Root CA.
- **Peer Verification**: The server requires and verifies client certificates. The client verifies the server's certificate against the Root CA and validates the `ServerName` against the certificate's SAN/CN.
- **Hardened Handshake**: Certificate verification happens at the TLS layer before any application data is exchanged.

### Granular Authorization (RBAC)
Beyond basic admission, `qconn` supports a granular Role-Based Access Control (RBAC) model defined by **Classes** and **Roles**.

#### Machine Classes (Attachment Types)
Clients are categorized into "Classes" (or Attachment Types) which define their functional identity.

#### Authorization Roles
A client's authorization status (associated with their certificate CN) can be mapped to one or more roles. Roles define what a client can *do* and with *which classes*:

- **Query**: Permission to enumerate and inspect connected devices of specific classes (e.g., a LIMS querying all Printers).
- **Submit**: Permission to send jobs/data to devices of specific classes.
- **Provide**: Permission to act as a receiver for jobs/data of specific classes.

#### Intent: Class-to-Class Communication
The authorization gate is designed to ensure that only authorized classes can talk to each other.

This multi-dimensional strategy (mTLS identity -> Authorized Status -> RBAC Role/Class) ensures that the transport is not just secure, but also functionally partitioned.

## Provisioning Workflow

`qconn` includes a built-in system for dynamic client provisioning:
1. **Request**: A new client creates creates a new certificate signed by a provisioning CA created from a provisioning token.
2. **Issuance**: The server's `CertificateAuthority` generates a new private key and signs a certificate for the client.
3. **Persist**: The client receives the credentials and saves them via its `CredentialStore`, then initiates its first connection.
