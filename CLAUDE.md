# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Run all tests
go test ./...

# Run tests for a specific package
go test ./qconn
go test ./anex
go test ./qclient

# Run a single test
go test -run TestFullConnectionLifecycle ./qconn

# Run tests with verbose output
go test -v ./...

# Build (no main package, library only)
go build ./...
```

## Architecture Overview

qconn is a hub-spoke secure transport library built on QUIC for real-time messaging. It has two main layers:

### Transport Layer (qconn package)
- **Client** (`qconn/client.go`): Resilient connection supervisor that maintains persistent QUIC connections, handles DNS re-resolution, automatic provisioning, and certificate renewal
- **Server** (`qconn/server.go`): QUIC listener managing client connections with mTLS authentication and authorization checks
- **CredentialStore/Resolver interfaces** (`qconn/interface.go`): Abstractions for credential persistence and hostname resolution

### Multiplexing Layer (anex package)
- **Hub** (`anex/anex.go`): Central message router between clients with role-based access control
- Addresses use a three-part tuple: `(Type, Machine, Device)` where Machine is identified by certificate fingerprint

### Supporting Packages
- **qdef**: Core type definitions, message structures (`Message`, `Identity`, `Addr`), stream routing, and certificate utilities
- **qclient**: High-level client API with generic request/response helpers and device provider abstraction
- **qmock**: Test mocks including `InMemoryAuthorizationManager`, `InMemoryCredentialStore`, `MockResolver`

## Key Design Patterns

### Message Flow
All messages are CBOR-encoded and follow the `qdef.Message` envelope containing target address, payload, and optional error. The `StreamRouter` dispatches to typed handlers registered via `qdef.Handle[Req, Resp]()`.

### Provisioning
Unprovisioned clients use a shared secret (provision token) to generate a derived CA, create a short-lived provisioning certificate, and request permanent credentials. Provisioning grants no operational access - clients idle until explicitly authorized by an administrator.

### Certificate Lifecycle
- CSR-based flow: clients generate keys locally, server signs CSRs (private keys never transmitted)
- Short validity periods (default 45 days) with automatic renewal at 15 days remaining
- Machine identity persists via certificate fingerprint (SHA-256 of cert raw bytes)
- Certificates contain identity only; roles are managed server-side

### Role-Based Authorization (anex)
- Roles define what job types a client can `Provide` (receive) and `SendsTo` (submit)
- Authorization is by fingerprint only (no hostname fallback)
- All message routing requires role authorization (no self-send bypass)
- `list-machines`: requires `SendsTo` permission (common for discovery/broadcast)
- `provision`: requires `SendsTo` permission (admin-only)
