# AGENTS.md

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

### Hostname Uniqueness
- Hostnames must be unique among active (authorized, non-expired) clients
- `SetClientStatus` checks atomically when authorizing; returns `ErrDuplicateHostname` on conflict
- Revoked or expired clients don't count; their hostnames become available again
- This ensures unambiguous message routing by hostname

### Role-Based Authorization (anex)
- Roles define what job types a client can `Provide` (receive) and `SendsTo` (submit)
- Authorization is by fingerprint only (no hostname fallback)
- All message routing requires role authorization (no self-send bypass)
- `list-machines`: requires `SendsTo` permission (common for discovery/broadcast)
- `provision`: requires `SendsTo` permission (admin-only)

### Message Protocol
- `MessageState int8`: Linear state machine tracking message progress (Unsent → Sent → ServerReceived → ResolvedMachine → ResolvedDevice → SentToTarget → TargetAck → TargetResponse → ForwardedResponse → ClientReceived)
- `MessageAction int8`: Purpose of message (Deliver=0, Ack=1, StatusUpdate=2)
- Clients may only send `MsgActionDeliver` to server; server validates and closes streams for invalid actions
- Server sends status updates to sender as message progresses through states
- Target client sends Ack to server upon receiving message, triggering transition from resolution timeout to job timeout

### Dual Timeout System
- **Resolution Timeout**: Time to find target and receive ack (default configurable via `ServerOpt.ResolutionTimeout`)
- **Job Timeout**: Time for target to respond after acking (default configurable via `ServerOpt.JobTimeout`)
- Ack extends deadline from resolution to job timeout, allowing slow handlers without routing failures

### MessageObserver
Server accepts `MessageObserver` interface for monitoring message lifecycle and collecting metrics on routing performance.

## Test Files

### Key Test Files
- `qconn/qconn_test.go`: Core connection lifecycle, migration, reliability tests
- `qconn/timeout_test.go`: Dual timeout system, ack mechanism, status updates, invalid action validation
- `qconn/expiry_test.go`: Certificate expiry detection and provisioning cert regeneration
- `qconn/race_test.go`: Concurrent access and race condition tests
- `qconn/clienthelper_test.go`: Generic handler registration and request/response helpers

### Testing Patterns
- Use `qmock.NewTestObserver` for tracking client state changes
- Use `waitForState(t, observer, state, timeout)` to wait for specific client states
- Raw QUIC connections can simulate misbehaving clients (see `TestInvalidAction_*` tests)
- Time manipulation via `timeNow` variable for testing certificate expiry scenarios

## Common Patterns

### Adding a New Handler
```go
// In qdef package - register typed handler
qdef.Handle(router, "service-type", func(ctx context.Context, id qdef.Identity, req *RequestType) (*ResponseType, error) {
    // Handle request
    return &ResponseType{...}, nil
})
```

### Client Request with Type Safety
```go
// Using qclient helpers
var response ResponseType
_, err := qclient.Request(ctx, client, target, request, &response)
```

### Server Validation
The server validates incoming messages in `handleStream()`:
- Only `MsgActionDeliver` is accepted from clients
- Invalid actions (Ack, StatusUpdate) cause stream closure and logging
- This prevents protocol abuse from misbehaving clients
