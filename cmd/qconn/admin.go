package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qstore"
)

// runAdminMode handles admin subcommands.
func runAdminMode(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printAdminUsage()
		return nil
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "auth":
		return runAdminAuth(ctx, subArgs)
	case "list":
		return runAdminList(ctx, subArgs)
	case "approve":
		return runAdminApprove(ctx, subArgs)
	case "revoke":
		return runAdminRevoke(ctx, subArgs)
	case "-h", "--help", "help":
		printAdminUsage()
		return nil
	default:
		return fmt.Errorf("unknown admin command: %s", subCmd)
	}
}

func printAdminUsage() {
	fmt.Fprintf(os.Stderr, `Usage: qconn admin <command> [options]

Commands:
  auth      Authenticate with server (provision + self-authorize)
  list      List connected clients
  approve   Approve a pending client
  revoke    Revoke a client's authorization

Run 'qconn admin <command> -h' for command-specific options.
`)
}

const defaultConfigPath = qstore.DefaultAdminStorePath

func newStore(p string) (qstore.DataStore, error) {
	return qstore.NewConfigDataStore(p)
}

func runAdminAuth(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin auth", flag.ExitOnError)
	var (
		server         string
		provisionToken string
		authToken      string
		configPath     string
	)
	fs.StringVar(&server, "server", "", "Server address (required)")
	fs.StringVar(&provisionToken, "provision-token", "", "Provision token (required for first auth)")
	fs.StringVar(&authToken, "auth-token", "", "Auth token for self-authorization (required)")
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if server == "" {
		return fmt.Errorf("-server is required")
	}
	if authToken == "" {
		return fmt.Errorf("-auth-token is required")
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "admin"
	}

	dataStore, err := newStore(configPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	store, err := newAdminCredentialStore(dataStore, hostname, provisionToken)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	defer store.Close()

	// Store server for future commands.
	if err := store.SetServer(server); err != nil {
		return fmt.Errorf("save server: %w", err)
	}

	// Connect.
	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr: server,
		Auth:       store,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	// Self-authorize.
	req := qconn.SelfAuthorizeRequest{Token: authToken}
	if err := client.Request(ctx, qconn.System(), "self-authorize", "", &req, nil); err != nil {
		return fmt.Errorf("self-authorize: %w", err)
	}

	fmt.Printf("Authenticated successfully\n")
	fmt.Printf("Fingerprint: %s\n", store.Fingerprint())
	fmt.Printf("Config saved to: %s\n", store.Path())
	return nil
}

func runAdminList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin list", flag.ExitOnError)
	var configPath string
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dataStore, err := newStore(configPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	store, err := newAdminCredentialStore(dataStore, "", "")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	defer store.Close()

	server := store.GetServer()
	if server == "" {
		return fmt.Errorf("no server configured; run 'qconn admin auth' first")
	}

	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr: server,
		Auth:       store,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	var clients []*qconn.ClientRecord
	if err := client.Request(ctx, qconn.System(), "admin/client/list", "admin", nil, &clients); err != nil {
		return fmt.Errorf("list: %w", err)
	}

	for _, c := range clients {
		status := c.Status.String()
		online := "offline"
		if c.Online {
			online = "online"
		}
		fmt.Printf("%s  %s  %s  %s  roles=%v\n",
			c.Fingerprint, c.Hostname, status, online, c.Roles)
	}
	return nil
}

func runAdminApprove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin approve", flag.ExitOnError)
	var (
		configPath string
		targetFP   string
		rolesJSON  string
	)
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	fs.StringVar(&targetFP, "fp", "", "Target fingerprint (required)")
	fs.StringVar(&rolesJSON, "roles", "", "JSON array of roles to assign")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if targetFP == "" {
		return fmt.Errorf("-fp is required")
	}

	fp, err := qconn.ParseFP(targetFP)
	if err != nil {
		return fmt.Errorf("parse fingerprint: %w", err)
	}

	roles, err := parseJSONStringSlice(rolesJSON)
	if err != nil {
		return fmt.Errorf("parse roles: %w", err)
	}

	dataStore, err := newStore(configPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	store, err := newAdminCredentialStore(dataStore, "", "")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	defer store.Close()

	server := store.GetServer()
	if server == "" {
		return fmt.Errorf("no server configured; run 'qconn admin auth' first")
	}

	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr: server,
		Auth:       store,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	req := qconn.AuthorizeClientRequest{
		FP:    fp,
		Roles: roles,
	}
	if err := client.Request(ctx, qconn.System(), "admin/client/auth", "admin", &req, nil); err != nil {
		return fmt.Errorf("approve: %w", err)
	}

	fmt.Printf("Approved client %s\n", fp)
	return nil
}

func runAdminRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin revoke", flag.ExitOnError)
	var (
		configPath string
		targetFP   string
	)
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	fs.StringVar(&targetFP, "fp", "", "Target fingerprint (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if targetFP == "" {
		return fmt.Errorf("-fp is required")
	}

	fp, err := qconn.ParseFP(targetFP)
	if err != nil {
		return fmt.Errorf("parse fingerprint: %w", err)
	}

	dataStore, err := newStore(configPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	store, err := newAdminCredentialStore(dataStore, "", "")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	defer store.Close()

	server := store.GetServer()
	if server == "" {
		return fmt.Errorf("no server configured; run 'qconn admin auth' first")
	}

	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr: server,
		Auth:       store,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	req := qconn.RevokeClientRequest{FP: fp}
	if err := client.Request(ctx, qconn.System(), "admin/client/revoke", "admin", &req, nil); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	fmt.Printf("Revoked client %s\n", fp)
	return nil
}

// Legacy types for backwards compatibility with tests.

// AdminOptions configures the admin mode (legacy).
type AdminOptions struct {
	ServerAddr     string
	CredentialsDir string
	ProvisionToken string
	AuthToken      string
	Command        string
	TargetFP       string
	RolesJSON      string
	MsgTypesJSON   string
}

// AdminResult contains the result of an admin operation (legacy).
type AdminResult struct {
	Clients []*qconn.ClientRecord
}

// RunAdmin runs admin operations (legacy API for tests).
func RunAdmin(ctx context.Context, opts *AdminOptions) error {
	result, err := RunAdminWithResult(ctx, opts)
	if err != nil {
		return err
	}

	if opts.Command == "list" && result != nil {
		for _, c := range result.Clients {
			status := c.Status.String()
			online := "offline"
			if c.Online {
				online = "online"
			}
			fmt.Printf("%s  %s  %s  %s  roles=%v\n",
				c.Fingerprint, c.Hostname, status, online, c.Roles)
		}
	}
	return nil
}

// RunAdminWithResult runs admin operations and returns the result (legacy API).
func RunAdminWithResult(ctx context.Context, opts *AdminOptions) (*AdminResult, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "admin"
	}

	store, err := qconn.NewFileCredentialStore(qconn.ClientStoreConfig{
		Dir:            opts.CredentialsDir,
		Hostname:       hostname,
		ProvisionToken: opts.ProvisionToken,
	})
	if err != nil {
		return nil, fmt.Errorf("create credential store: %w", err)
	}
	defer store.Close()

	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr: opts.ServerAddr,
		Auth:       store,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to server: %w", err)
	}
	defer client.Close()

	if opts.AuthToken != "" {
		req := qconn.SelfAuthorizeRequest{Token: opts.AuthToken}
		if err := client.Request(ctx, qconn.System(), "self-authorize", "", &req, nil); err != nil {
			return nil, fmt.Errorf("self-authorize: %w", err)
		}
		fmt.Println("Self-authorized successfully")
	}

	switch opts.Command {
	case "list":
		var clients []*qconn.ClientRecord
		if err := client.Request(ctx, qconn.System(), "admin/client/list", "admin", nil, &clients); err != nil {
			return nil, fmt.Errorf("list clients: %w", err)
		}
		return &AdminResult{Clients: clients}, nil
	case "approve":
		if opts.TargetFP == "" {
			return nil, fmt.Errorf("target fingerprint required (-fp)")
		}
		fp, err := qconn.ParseFP(opts.TargetFP)
		if err != nil {
			return nil, fmt.Errorf("parse fingerprint: %w", err)
		}
		roles, _ := parseJSONStringSlice(opts.RolesJSON)
		msgTypes, _ := parseJSONStringSlice(opts.MsgTypesJSON)
		req := qconn.AuthorizeClientRequest{FP: fp, Roles: roles, MsgTypes: msgTypes}
		if err := client.Request(ctx, qconn.System(), "admin/client/auth", "admin", &req, nil); err != nil {
			return nil, fmt.Errorf("approve client: %w", err)
		}
		fmt.Printf("Approved client %s\n", fp)
		return nil, nil
	case "revoke":
		if opts.TargetFP == "" {
			return nil, fmt.Errorf("target fingerprint required (-fp)")
		}
		fp, err := qconn.ParseFP(opts.TargetFP)
		if err != nil {
			return nil, fmt.Errorf("parse fingerprint: %w", err)
		}
		req := qconn.RevokeClientRequest{FP: fp}
		if err := client.Request(ctx, qconn.System(), "admin/client/revoke", "admin", &req, nil); err != nil {
			return nil, fmt.Errorf("revoke client: %w", err)
		}
		fmt.Printf("Revoked client %s\n", fp)
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown command: %s", opts.Command)
	}
}
