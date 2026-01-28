package qexec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kardianos/qconn"
)

// CmdServerStart starts the qconn server.
type CmdServerStart struct {
	ListenAddr string
	ConfigFile string

	// Internal fields for testing.
	DBPath          string
	ProvisionTokens []string
	Roles           map[string]*qconn.RoleConfig
}

// ServerConfig is the JSON configuration file format for the server.
type ServerConfig struct {
	DBPath          string                      `json:"db_path,omitempty"`
	ProvisionTokens []string                    `json:"provision_tokens"`
	Roles           map[string]*qconn.RoleConfig `json:"roles"`
}

// Execute implements ServerCommand.
func (cmd *CmdServerStart) Execute(ctx context.Context, responses chan<- any) error {
	var cfg *ServerConfig

	// If internal fields are set, use them directly (for testing).
	if cmd.DBPath != "" || len(cmd.ProvisionTokens) > 0 || len(cmd.Roles) > 0 {
		cfg = &ServerConfig{
			DBPath:          cmd.DBPath,
			ProvisionTokens: cmd.ProvisionTokens,
			Roles:           cmd.Roles,
		}
	} else {
		// Load configuration from file.
		var err error
		cfg, err = loadServerConfig(cmd.ConfigFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
	}

	dbPath := cfg.DBPath
	if dbPath == "" {
		return fmt.Errorf("database path is required (-db or db_path in config)")
	}

	// Ensure parent directory exists.
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create database directory: %w", err)
		}
	}

	// Create auth manager.
	auth, isNew, err := qconn.NewBoltAuthManager(qconn.BoltAuthConfig{
		DBPath:          dbPath,
		ProvisionTokens: cfg.ProvisionTokens,
		Roles:           cfg.Roles,
	})
	if err != nil {
		return fmt.Errorf("create auth manager: %w", err)
	}
	defer auth.Close()

	// Start cleanup.
	auth.StartCleanup(time.Hour)

	// Create auth token if this is a new database.
	var authToken qconn.TA
	if isNew {
		authToken, err = auth.CreateAuthToken()
		if err != nil {
			return fmt.Errorf("create auth token: %w", err)
		}
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
	conn, err := net.ListenPacket("udp", cmd.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().String()

	// Send ready response.
	responses <- &RespServerReady{
		Addr:      addr,
		AuthToken: authToken,
	}

	// Run server.
	return server.Serve(ctx, conn)
}

// loadServerConfig loads server configuration from a JSON file.
func loadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &cfg, nil
}

// CmdAdminAuth authenticates with the server (provision + self-authorize).
type CmdAdminAuth struct {
	ServerAddr     string
	ConfigPath     string
	ProvisionToken string
	AuthToken      string
	Hostname       string
}

// ConnectConfig implements ClientCommand.
func (c *CmdAdminAuth) ConnectConfig() ConnectConfig {
	hostname := c.Hostname
	if hostname == "" {
		hostname = "admin"
	}
	return ConnectConfig{
		ConfigPath:     c.ConfigPath,
		ServerAddr:     c.ServerAddr,
		ProvisionToken: c.ProvisionToken,
		Hostname:       hostname,
	}
}

// Execute implements ClientCommand.
func (c *CmdAdminAuth) Execute(ctx context.Context, conn *ConnectResult, responses chan<- any) error {
	authToken, err := qconn.ParseTA(c.AuthToken)
	if err != nil {
		return err
	}

	// Self-authorize.
	req := qconn.SelfAuthorizeRequest{Token: authToken}
	if err := conn.Client.Request(ctx, qconn.System(), "", &req, nil); err != nil {
		return fmt.Errorf("self-authorize: %w", err)
	}

	// Approve self with admin role.
	fp := conn.Creds.Fingerprint()
	approveReq := qconn.AuthorizeClientRequest{
		FP:    fp,
		Roles: []string{"admin"},
	}
	if err := conn.Client.Request(ctx, qconn.System(), "admin", &approveReq, nil); err != nil {
		return fmt.Errorf("approve self with admin role: %w", err)
	}

	responses <- &RespAdminAuthed{
		Fingerprint: fp,
		ConfigPath:  conn.Creds.Store().Path(),
	}

	return nil
}

// CmdAdminList lists connected clients.
type CmdAdminList struct {
	ServerAddr string
	ConfigPath string
}

// ConnectConfig implements ClientCommand.
func (c *CmdAdminList) ConnectConfig() ConnectConfig {
	return ConnectConfig{
		ConfigPath:  c.ConfigPath,
		ServerAddr:  c.ServerAddr,
		DefaultRole: "admin",
	}
}

// Execute implements ClientCommand.
func (c *CmdAdminList) Execute(ctx context.Context, conn *ConnectResult, responses chan<- any) error {
	var clients []*qconn.ClientRecord
	req := qconn.AdminClientListRequest{}
	if err := conn.Client.Request(ctx, qconn.System(), "admin", &req, &clients); err != nil {
		return fmt.Errorf("list: %w", err)
	}

	responses <- &RespClientList{Clients: clients}
	return nil
}

// CmdAdminApprove approves a pending client.
type CmdAdminApprove struct {
	ServerAddr string
	ConfigPath string
	TargetFP   qconn.FP
	Roles      []string
	MsgTypes   []string
}

// ConnectConfig implements ClientCommand.
func (c *CmdAdminApprove) ConnectConfig() ConnectConfig {
	return ConnectConfig{
		ConfigPath:  c.ConfigPath,
		ServerAddr:  c.ServerAddr,
		DefaultRole: "admin",
	}
}

// Execute implements ClientCommand.
func (c *CmdAdminApprove) Execute(ctx context.Context, conn *ConnectResult, responses chan<- any) error {
	req := qconn.AuthorizeClientRequest{
		FP:       c.TargetFP,
		Roles:    c.Roles,
		MsgTypes: c.MsgTypes,
	}
	if err := conn.Client.Request(ctx, qconn.System(), "admin", &req, nil); err != nil {
		return fmt.Errorf("approve: %w", err)
	}

	responses <- &RespApproved{Fingerprint: c.TargetFP}
	return nil
}

// CmdAdminRevoke revokes a client's authorization.
type CmdAdminRevoke struct {
	ServerAddr string
	ConfigPath string
	TargetFP   qconn.FP
}

// ConnectConfig implements ClientCommand.
func (c *CmdAdminRevoke) ConnectConfig() ConnectConfig {
	return ConnectConfig{
		ConfigPath:  c.ConfigPath,
		ServerAddr:  c.ServerAddr,
		DefaultRole: "admin",
	}
}

// Execute implements ClientCommand.
func (c *CmdAdminRevoke) Execute(ctx context.Context, conn *ConnectResult, responses chan<- any) error {
	req := qconn.RevokeClientRequest{FP: c.TargetFP}
	if err := conn.Client.Request(ctx, qconn.System(), "admin", &req, nil); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	responses <- &RespRevoked{Fingerprint: c.TargetFP}
	return nil
}

// CmdAdminRotateToken sends a new provision token to an authenticated client.
type CmdAdminRotateToken struct {
	ServerAddr string
	ConfigPath string
	TargetFP   qconn.FP
	Token      string
}

// ConnectConfig implements ClientCommand.
func (c *CmdAdminRotateToken) ConnectConfig() ConnectConfig {
	return ConnectConfig{
		ConfigPath:  c.ConfigPath,
		ServerAddr:  c.ServerAddr,
		DefaultRole: "admin",
	}
}

// Execute implements ClientCommand.
func (c *CmdAdminRotateToken) Execute(ctx context.Context, conn *ConnectResult, responses chan<- any) error {
	req := qconn.RotateTokenRequest{FP: c.TargetFP, Token: c.Token}
	if err := conn.Client.Request(ctx, qconn.System(), "admin", &req, nil); err != nil {
		return fmt.Errorf("rotate token: %w", err)
	}

	responses <- &RespTokenRotated{Fingerprint: c.TargetFP}
	return nil
}

// CmdAdminTriggerRenewal triggers certificate renewal on an authenticated client.
type CmdAdminTriggerRenewal struct {
	ServerAddr string
	ConfigPath string
	TargetFP   qconn.FP
}

// ConnectConfig implements ClientCommand.
func (c *CmdAdminTriggerRenewal) ConnectConfig() ConnectConfig {
	return ConnectConfig{
		ConfigPath:  c.ConfigPath,
		ServerAddr:  c.ServerAddr,
		DefaultRole: "admin",
	}
}

// Execute implements ClientCommand.
func (c *CmdAdminTriggerRenewal) Execute(ctx context.Context, conn *ConnectResult, responses chan<- any) error {
	req := qconn.TriggerRenewalRequest{FP: c.TargetFP}
	if err := conn.Client.Request(ctx, qconn.System(), "admin", &req, nil); err != nil {
		return fmt.Errorf("trigger renewal: %w", err)
	}

	responses <- &RespRenewalTriggered{Fingerprint: c.TargetFP}
	return nil
}
