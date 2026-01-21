package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kardianos/qconn"
)

// ServerOptions configures the server mode.
type ServerOptions struct {
	ListenAddr         string
	DataDir            string
	ProvisionTokensJSON string
	RolesJSON          string
}

// ServerResult contains information about the running server.
type ServerResult struct {
	AuthToken string // The auth token for admin self-authorization
	Addr      string // The actual listening address
}

// RunServer starts the qconn server with the given options.
// It blocks until the context is cancelled.
// If resultCh is provided, it sends the ServerResult after startup.
func RunServer(ctx context.Context, opts *ServerOptions) error {
	return RunServerWithResult(ctx, opts, nil)
}

// RunServerWithResult starts the server and optionally reports startup info.
func RunServerWithResult(ctx context.Context, opts *ServerOptions, resultCh chan<- *ServerResult) error {
	// Ensure data directory exists.
	if err := os.MkdirAll(opts.DataDir, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	// Parse provision tokens.
	provisionTokens, err := parseJSONStringSlice(opts.ProvisionTokensJSON)
	if err != nil {
		return fmt.Errorf("parse provision tokens: %w", err)
	}

	// Parse roles.
	roles, err := parseRoles(opts.RolesJSON)
	if err != nil {
		return fmt.Errorf("parse roles: %w", err)
	}

	// Create auth manager.
	dbPath := filepath.Join(opts.DataDir, "auth.db")
	auth, isNew, err := qconn.NewBoltAuthManager(qconn.BoltAuthConfig{
		DBPath:          dbPath,
		ProvisionTokens: provisionTokens,
		Roles:           roles,
	})
	if err != nil {
		return fmt.Errorf("create auth manager: %w", err)
	}
	defer auth.Close()

	// Start cleanup.
	auth.StartCleanup(time.Hour)

	// Create auth token if this is a new database.
	var authToken string
	if isNew {
		authToken, err = auth.CreateAuthToken()
		if err != nil {
			return fmt.Errorf("create auth token: %w", err)
		}
		fmt.Printf("New database created. Auth token: %s\n", authToken)
	}

	// Create server.
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	// Listen on UDP.
	conn, err := net.ListenPacket("udp", opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().String()
	fmt.Printf("Server listening on %s\n", addr)

	// Send result if channel provided.
	if resultCh != nil {
		resultCh <- &ServerResult{
			AuthToken: authToken,
			Addr:      addr,
		}
	}

	// Run server.
	return server.Serve(ctx, conn)
}
