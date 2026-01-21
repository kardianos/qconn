package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/qconn"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1]
	args := os.Args[2:]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	var err error
	switch mode {
	case "server":
		err = runServerMode(ctx, args)
	case "admin":
		err = runAdminMode(ctx, args)
	case "time-provider":
		err = runTimeProviderMode(ctx, args)
	case "time-consumer":
		err = runTimeConsumerMode(ctx, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", mode)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: qconn <mode> [options]

Modes:
  server          Start the qconn server
  admin           Run admin operations (list, approve, revoke)
  time-provider   Start a client that provides a time endpoint
  time-consumer   Start a client that consumes the time endpoint

Run 'qconn <mode> -h' for mode-specific options.
`)
}

func runServerMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	opts := &ServerOptions{}
	fs.StringVar(&opts.ListenAddr, "listen", "127.0.0.1:9443", "Address to listen on")
	fs.StringVar(&opts.DataDir, "data", "./data", "Data directory for database")
	fs.StringVar(&opts.ProvisionTokensJSON, "provision-tokens", "", "JSON array of provision tokens")
	fs.StringVar(&opts.RolesJSON, "roles", "", `JSON role config. Schema: {"role": {"submit": [...], "provide": [...]}}
    	Example: {"admin":{"submit":["admin/client/list","admin/client/auth","admin/client/revoke"]},"time-provider":{"provide":["time"]},"time-consumer":{"submit":["time"]}}`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return RunServer(ctx, opts)
}

func runAdminMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	opts := &AdminOptions{}
	fs.StringVar(&opts.ServerAddr, "server", "127.0.0.1:9443", "Server address")
	fs.StringVar(&opts.CredentialsDir, "creds", "./admin-creds", "Credentials directory")
	fs.StringVar(&opts.ProvisionToken, "provision-token", "", "Provision token for initial setup")
	fs.StringVar(&opts.AuthToken, "auth-token", "", "Auth token for self-authorization")
	fs.StringVar(&opts.Command, "cmd", "list", "Command: list, approve, revoke")
	fs.StringVar(&opts.TargetFP, "fp", "", "Target client fingerprint (for approve/revoke)")
	fs.StringVar(&opts.RolesJSON, "roles", "", "JSON array of roles to assign (for approve)")
	fs.StringVar(&opts.MsgTypesJSON, "msg-types", "", "JSON array of message types to authorize (for approve)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return RunAdmin(ctx, opts)
}

func runTimeProviderMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("time-provider", flag.ExitOnError)
	opts := &TimeProviderOptions{}
	fs.StringVar(&opts.ServerAddr, "server", "127.0.0.1:9443", "Server address")
	fs.StringVar(&opts.CredentialsDir, "creds", "./time-provider-creds", "Credentials directory")
	fs.StringVar(&opts.ProvisionToken, "provision-token", "", "Provision token for initial setup")
	fs.StringVar(&opts.Hostname, "hostname", "time-provider", "Client hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return RunTimeProvider(ctx, opts)
}

func runTimeConsumerMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("time-consumer", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "time-consumer uses the \"time-consumer\" role to request time.\n\n")
		fs.PrintDefaults()
	}
	opts := &TimeConsumerOptions{}
	fs.StringVar(&opts.ServerAddr, "server", "127.0.0.1:9443", "Server address")
	fs.StringVar(&opts.CredentialsDir, "creds", "./time-consumer-creds", "Credentials directory")
	fs.StringVar(&opts.ProvisionToken, "provision-token", "", "Provision token for initial setup")
	fs.StringVar(&opts.Hostname, "hostname", "time-consumer", "Client hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return RunTimeConsumer(ctx, opts)
}

// parseJSONStringSlice parses a JSON array of strings.
func parseJSONStringSlice(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var result []string
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON array: %w", err)
	}
	return result, nil
}

// parseRoles parses a JSON object mapping role names to role configs.
func parseRoles(s string) (map[string]*qconn.RoleConfig, error) {
	if s == "" {
		return nil, nil
	}
	var result map[string]*qconn.RoleConfig
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return nil, fmt.Errorf("invalid roles JSON: %w", err)
	}
	return result, nil
}
