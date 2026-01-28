package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qexec"
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
	case "rotate-token":
		return runAdminRotateToken(ctx, subArgs)
	case "trigger-renewal":
		return runAdminTriggerRenewal(ctx, subArgs)
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
  auth             Authenticate with server (provision + self-authorize)
  list             List connected clients
  approve          Approve a pending client
  revoke           Revoke a client's authorization
  rotate-token     Send new provision token to client
  trigger-renewal  Trigger certificate renewal on client

Run 'qconn admin <command> -h' for command-specific options.
`)
}

const defaultConfigPath = qstore.DefaultAdminStorePath

func runAdminAuth(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin auth", flag.ExitOnError)
	var (
		server         string
		provisionToken string
		authToken      string
		configPath     string
		hostname       string
	)
	fs.StringVar(&server, "server", "", "Server address (required)")
	fs.StringVar(&provisionToken, "provision-token", "", "Provision token (required for first auth)")
	fs.StringVar(&authToken, "auth-token", "", "Auth token for self-authorization (required)")
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	fs.StringVar(&hostname, "hostname", "admin", "Hostname for this admin client")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if server == "" {
		return fmt.Errorf("-server is required")
	}
	if authToken == "" {
		return fmt.Errorf("-auth-token is required")
	}

	cmd := &qexec.CmdAdminAuth{
		ServerAddr:     server,
		ConfigPath:     configPath,
		ProvisionToken: provisionToken,
		AuthToken:      authToken,
		Hostname:       hostname,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespAdminAuthed:
			fmt.Printf("Authenticated and approved as admin\n")
			fmt.Printf("Fingerprint: %s\n", r.Fingerprint)
			fmt.Printf("Config saved to: %s\n", r.ConfigPath)
		}
	}

	return <-errCh
}

func runAdminList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin list", flag.ExitOnError)
	var configPath string
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cmd := &qexec.CmdAdminList{
		ConfigPath: configPath,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespClientList:
			for _, c := range r.Clients {
				status := c.Status.String()
				online := "offline"
				if c.Online {
					online = "online"
				}
				fmt.Printf("%s  %s  %s  %s  roles=%v req-roles=%v devs=%v\n", c.Fingerprint, c.Hostname, status, online, c.Roles, c.RequestedRoles, c.Devices)
			}
		}
	}

	return <-errCh
}

func runAdminApprove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin approve", flag.ExitOnError)
	var (
		configPath  string
		targetFP    string
		rolesCSV    string
		useReqRoles bool
	)
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	fs.StringVar(&targetFP, "fp", "", "Target fingerprint (required)")
	fs.StringVar(&rolesCSV, "roles", "", "comma separated list of roles to assign")
	fs.BoolVar(&useReqRoles, "req-roles", false, "Use client's requested roles instead of -roles")
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

	var roles []string
	if useReqRoles {
		// Fetch client's requested roles from the server.
		reqRoles, err := getClientRequestedRoles(ctx, configPath, fp)
		if err != nil {
			return fmt.Errorf("get requested roles: %w", err)
		}
		if len(reqRoles) == 0 {
			return fmt.Errorf("client %s has no requested roles", fp)
		}
		roles = reqRoles
		fmt.Printf("Using requested roles: %v\n", roles)
	} else {
		roles = parseCSVStringSlice(rolesCSV)
	}

	cmd := &qexec.CmdAdminApprove{
		ConfigPath: configPath,
		TargetFP:   fp,
		Roles:      roles,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespApproved:
			fmt.Printf("Approved client %s\n", r.Fingerprint)
		}
	}

	return <-errCh
}

// getClientRequestedRoles fetches a client's requested roles from the server.
func getClientRequestedRoles(ctx context.Context, configPath string, fp qconn.FP) ([]string, error) {
	cmd := &qexec.CmdAdminList{
		ConfigPath: configPath,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	var requestedRoles []string
	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespClientList:
			for _, c := range r.Clients {
				if c.Fingerprint == fp {
					requestedRoles = c.RequestedRoles
					break
				}
			}
		}
	}

	if err := <-errCh; err != nil {
		return nil, err
	}

	return requestedRoles, nil
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

	cmd := &qexec.CmdAdminRevoke{
		ConfigPath: configPath,
		TargetFP:   fp,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespRevoked:
			fmt.Printf("Revoked client %s\n", r.Fingerprint)
		}
	}

	return <-errCh
}

// parseCSVStringSlice parses a comma-separated string into a slice.
func parseCSVStringSlice(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func runAdminRotateToken(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin rotate-token", flag.ExitOnError)
	var (
		configPath string
		targetFP   string
		token      string
	)
	fs.StringVar(&configPath, "config", defaultConfigPath, "Config file path")
	fs.StringVar(&targetFP, "fp", "", "Target fingerprint (required)")
	fs.StringVar(&token, "token", "", "New provision token (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if targetFP == "" {
		return fmt.Errorf("-fp is required")
	}
	if token == "" {
		return fmt.Errorf("-token is required")
	}

	fp, err := qconn.ParseFP(targetFP)
	if err != nil {
		return fmt.Errorf("parse fingerprint: %w", err)
	}

	cmd := &qexec.CmdAdminRotateToken{
		ConfigPath: configPath,
		TargetFP:   fp,
		Token:      token,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespTokenRotated:
			fmt.Printf("Token rotated for client %s\n", r.Fingerprint)
		}
	}

	return <-errCh
}

func runAdminTriggerRenewal(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin trigger-renewal", flag.ExitOnError)
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

	cmd := &qexec.CmdAdminTriggerRenewal{
		ConfigPath: configPath,
		TargetFP:   fp,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *qexec.RespRenewalTriggered:
			fmt.Printf("Renewal triggered for client %s\n", r.Fingerprint)
		}
	}

	return <-errCh
}
