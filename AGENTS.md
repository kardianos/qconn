# AGENTS.md

Guidance for Claude Code when working with this repository.

## Build and Test

```bash
go test ./...                              # All tests
go test ./qstore                           # Single package
go test -run TestClientToClient ./...      # Single test
go build ./...                             # Build all
```

## Package Structure

| Package | Purpose |
|---------|---------|
| `qconn` (root) | Client, Server, credential stores, auth management |
| `qstore` | DataStore interface, config file format, encryption |
| `bech32` | Fingerprint encoding |
| `cmd/qconn` | CLI admin tool |

## Key Files

- `client.go` - QUIC client with auto-reconnect and provisioning
- `server.go` - QUIC server with mTLS and message routing
- `auth.go` - BoltDB-backed auth manager
- `store_data.go` - ClientCredential wrapping DataStore
- `qstore/store_config.go` - Config file format (T{text}, B{base64})
- `qstore/datastore.go` - DataStore interface

## Testing Patterns

```go
// Use test helpers for state observation
observer := NewTestObserver()
client, _ := NewClient(ctx, ClientOpt{...})
waitForState(t, observer, StateConnected, 5*time.Second)

// Time manipulation for expiry tests
oldTimeNow := timeNow
timeNow = func() time.Time { return fixedTime }
defer func() { timeNow = oldTimeNow }()
```

## Common Tasks

### Adding a message handler
Register in the server's handler map, implement the handler function.

### Adding a DataStore implementation
Implement `Get`, `Set`, `Path` methods from `qstore.DataStore` interface.

### Modifying config format
Update `qstore/store_config.go` and corresponding tests in `store_config_test.go`.
