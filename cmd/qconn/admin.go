package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kardianos/qconn"
)

// AdminOptions configures the admin mode.
type AdminOptions struct {
	ServerAddr     string
	CredentialsDir string
	ProvisionToken string
	AuthToken      string
	Command        string // list, approve, revoke
	TargetFP       string // For approve/revoke
	RolesJSON      string // For approve
	MsgTypesJSON   string // For approve
}

// AdminResult contains the result of an admin operation.
type AdminResult struct {
	Clients []*qconn.ClientRecord // For list command
}

// RunAdmin runs admin operations.
func RunAdmin(ctx context.Context, opts *AdminOptions) error {
	result, err := RunAdminWithResult(ctx, opts)
	if err != nil {
		return err
	}

	// Print result for CLI usage.
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

// RunAdminWithResult runs admin operations and returns the result.
func RunAdminWithResult(ctx context.Context, opts *AdminOptions) (*AdminResult, error) {
	// Create credential store.
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

	// Connect to server.
	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr: opts.ServerAddr,
		Auth:       store,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to server: %w", err)
	}
	defer client.Close()

	// If auth token provided, self-authorize.
	if opts.AuthToken != "" {
		req := qconn.SelfAuthorizeRequest{Token: opts.AuthToken}
		if err := client.Request(ctx, qconn.System(), "self-authorize", "", &req, nil); err != nil {
			return nil, fmt.Errorf("self-authorize: %w", err)
		}
		fmt.Println("Self-authorized successfully")
	}

	// Execute command.
	switch opts.Command {
	case "list":
		return adminList(ctx, client)
	case "approve":
		return nil, adminApprove(ctx, client, opts)
	case "revoke":
		return nil, adminRevoke(ctx, client, opts)
	default:
		return nil, fmt.Errorf("unknown command: %s", opts.Command)
	}
}

func adminList(ctx context.Context, client *qconn.Client) (*AdminResult, error) {
	var clients []*qconn.ClientRecord
	if err := client.Request(ctx, qconn.System(), "admin/client/list", "admin", nil, &clients); err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	return &AdminResult{Clients: clients}, nil
}

func adminApprove(ctx context.Context, client *qconn.Client, opts *AdminOptions) error {
	if opts.TargetFP == "" {
		return fmt.Errorf("target fingerprint required (-fp)")
	}

	fp, err := qconn.ParseFP(opts.TargetFP)
	if err != nil {
		return fmt.Errorf("parse fingerprint: %w", err)
	}

	roles, err := parseJSONStringSlice(opts.RolesJSON)
	if err != nil {
		return fmt.Errorf("parse roles: %w", err)
	}

	msgTypes, err := parseJSONStringSlice(opts.MsgTypesJSON)
	if err != nil {
		return fmt.Errorf("parse msg types: %w", err)
	}

	req := qconn.AuthorizeClientRequest{
		FP:       fp,
		Roles:    roles,
		MsgTypes: msgTypes,
	}
	if err := client.Request(ctx, qconn.System(), "admin/client/auth", "admin", &req, nil); err != nil {
		return fmt.Errorf("approve client: %w", err)
	}
	fmt.Printf("Approved client %s\n", fp)
	return nil
}

func adminRevoke(ctx context.Context, client *qconn.Client, opts *AdminOptions) error {
	if opts.TargetFP == "" {
		return fmt.Errorf("target fingerprint required (-fp)")
	}

	fp, err := qconn.ParseFP(opts.TargetFP)
	if err != nil {
		return fmt.Errorf("parse fingerprint: %w", err)
	}

	req := qconn.RevokeClientRequest{FP: fp}
	if err := client.Request(ctx, qconn.System(), "admin/client/revoke", "admin", &req, nil); err != nil {
		return fmt.Errorf("revoke client: %w", err)
	}
	fmt.Printf("Revoked client %s\n", fp)
	return nil
}

// Helper for JSON parsing (also used by main.go).
func init() {
	// Ensure parseJSONStringSlice is available.
	_ = json.Unmarshal
}
