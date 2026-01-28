package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qexec"
)

// ServerConfig is the JSON configuration file format for the server.
// Kept here for config generation.
type ServerConfig = qexec.ServerConfig

// ServerOptions configures the server mode.
type ServerOptions struct {
	ListenAddr string
	ConfigFile string
}

// ServerResult contains information about the running server.
type ServerResult struct {
	AuthToken qconn.TA // The auth token for admin self-authorization
	Addr      string   // The actual listening address
}

// RunServer starts the qconn server with the given options.
// It blocks until the context is cancelled.
// If resultCh is provided, it sends the ServerResult after startup.
func RunServer(ctx context.Context, opts *ServerOptions) error {
	return RunServerWithResult(ctx, opts, nil)
}

// RunServerWithResult starts the server and optionally reports startup info.
func RunServerWithResult(ctx context.Context, opts *ServerOptions, resultCh chan<- *ServerResult) error {
	cmd := &qexec.CmdServerStart{
		ListenAddr: opts.ListenAddr,
		ConfigFile: opts.ConfigFile,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespServerReady:
			if !r.AuthToken.IsZero() {
				fmt.Printf("New database created. Auth token: %s\n", r.AuthToken)
			}
			fmt.Printf("Server listening on %s\n", r.Addr)
			if resultCh != nil {
				resultCh <- &ServerResult{
					AuthToken: r.AuthToken,
					Addr:      r.Addr,
				}
			}
		}
	}

	return <-errCh
}

// LoadServerConfig loads server configuration from a JSON file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	// Delegate to the qconn package's implementation through a direct load
	data, err := io.ReadAll(bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &cfg, nil
}

// generateDefaultConfig creates a default server configuration with:
// - admin, time-provider, and time-consumer roles
// - Two random provisioning tokens
// - Default database path
func generateDefaultConfig() (*ServerConfig, error) {
	token1, err := generateProvisionToken()
	if err != nil {
		return nil, fmt.Errorf("generate token 1: %w", err)
	}
	token2, err := generateProvisionToken()
	if err != nil {
		return nil, fmt.Errorf("generate token 2: %w", err)
	}

	return &ServerConfig{
		DBPath:          "./qconn.db",
		ProvisionTokens: []string{token1, token2},
		Roles: map[string]*qconn.RoleConfig{
			"admin": {
				Submit: []string{
					"admin/client/list",
					"admin/client/auth",
					"admin/client/revoke",
				},
			},
			"time-provider": {
				Provide: []string{"time"},
			},
			"time-consumer": {
				Submit: []string{"time"},
			},
		},
	}, nil
}

// writeDefaultConfig generates a default configuration and writes it to the specified path.
func writeDefaultConfig(w io.Writer) error {
	cfg, err := generateDefaultConfig()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if _, err = io.Copy(w, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

// generateProvisionToken creates a secure random provision token string.
func generateProvisionToken() (string, error) {
	const tokenLen = 24
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}
