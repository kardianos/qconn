package qexec

import (
	"context"
	"fmt"
	"time"

	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qstore"
)

// ServerCommand executes server-side operations that don't require a client connection.
type ServerCommand interface {
	Execute(ctx context.Context, responses chan<- any) error
}

// ClientCommand executes client-side operations with an established connection.
type ClientCommand interface {
	ConnectConfig() ConnectConfig
	Execute(ctx context.Context, conn *ConnectResult, responses chan<- any) error
}

// Execute runs a command and streams responses to the channel.
// The channel is closed when execution completes.
// For ClientCommand, the connection is created and managed automatically.
func Execute(ctx context.Context, cmd any, responses chan<- any) error {
	defer close(responses)

	switch c := cmd.(type) {
	case ServerCommand:
		return c.Execute(ctx, responses)
	case ClientCommand:
		conn, err := ConnectClient(ctx, c.ConnectConfig())
		if err != nil {
			return err
		}
		defer conn.Close()
		return c.Execute(ctx, conn, responses)
	default:
		return fmt.Errorf("command must implement ServerCommand or ClientCommand: %T", cmd)
	}
}

// ConnectConfig configures a client connection.
type ConnectConfig struct {
	ConfigPath     string        // Required: path to config file
	ServerAddr     string        // Optional: server address (read from store if empty)
	ProvisionToken string        // Optional: provision token (read from store if empty)
	Hostname       string        // Optional: hostname for provisioning
	Handler        qconn.Handler // Optional: handler for incoming requests
	DefaultRole    string        // Optional: default role for requests

	// OnReconnect is called after a successful reconnection to re-register state.
	OnReconnect func(ctx context.Context, c *qconn.Client) error
	// MaxIdleTimeout controls how quickly a dead server is detected.
	// Valid range: 500ms to 600s. Values outside this range are clamped.
	// Default is 30 seconds if not specified.
	MaxIdleTimeout time.Duration
}

// ConnectResult holds the connected client and related resources.
type ConnectResult struct {
	Client *qconn.Client
	Creds  *qconn.ClientCredential
	Store  qstore.DataStore // Client namespace store
}

// Close releases all resources.
func (r *ConnectResult) Close() {
	if r.Client != nil {
		r.Client.Close()
	}
	if r.Creds != nil {
		r.Creds.Close()
	}
}

// ConnectClient creates a client connection using the provided configuration.
// The caller must call result.Close() when done.
func ConnectClient(ctx context.Context, cfg ConnectConfig) (*ConnectResult, error) {
	if cfg.ConfigPath == "" {
		return nil, fmt.Errorf("ConfigPath is required")
	}

	// Create backing data store.
	baseStore, err := qstore.NewConfigDataStore(cfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("create data store: %w", err)
	}

	// Create namespaced stores.
	ns := qstore.NewNS(baseStore)
	authStore := ns.Add("auth")     // For credentials (cert, key, root-ca, provision-token)
	clientStore := ns.Add("client") // For client config (server address)

	// Create credential store with auth namespace.
	// Provision token is stored in auth store alongside credentials.
	credStore, err := qconn.NewClientCredential(qconn.ClientCredentialConfig{
		Store:          authStore,
		Hostname:       cfg.Hostname,
		ProvisionToken: cfg.ProvisionToken,
	})
	if err != nil {
		return nil, fmt.Errorf("create credential store: %w", err)
	}

	// Create client with client namespace for server address storage.
	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr:         cfg.ServerAddr,
		Auth:               credStore,
		Store:              clientStore,
		Handler:            cfg.Handler,
		DefaultRequestRole: cfg.DefaultRole,
		OnReconnect:        cfg.OnReconnect,
		MaxIdleTimeout:     cfg.MaxIdleTimeout,
	})
	if err != nil {
		credStore.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}

	return &ConnectResult{
		Client: client,
		Creds:  credStore,
		Store:  clientStore,
	}, nil
}
