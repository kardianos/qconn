package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
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

	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")

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
  admin           Admin operations (auth, list, approve, revoke)
  time-provider   Start a client that provides a time endpoint
  time-consumer   Start a client that consumes the time endpoint

Run 'qconn <mode> -h' for mode-specific options.
`)
}

func runServerMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	opts := &ServerOptions{}
	var genConfig bool
	fs.StringVar(&opts.ListenAddr, "listen", "127.0.0.1:9443", "Address to listen on")
	fs.StringVar(&opts.ConfigFile, "config", "config.json", "Path to JSON configuration file")
	fs.BoolVar(&genConfig, "gen-config", false, "Generate a default config file to stdout or config flag if provided and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Generate config and exit if requested.
	if genConfig {
		var w io.Writer = os.Stdout
		if len(opts.ConfigFile) > 0 {
			f, err := os.OpenFile(opts.ConfigFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
			if err != nil {
				return fmt.Errorf("unable to open config %q file to write to it: %w", opts.ConfigFile, err)
			}
			defer f.Close()

			w = f
		}
		if err := writeDefaultConfig(w); err != nil {
			return fmt.Errorf("generate config: %w", err)
		}
		return nil
	}

	// Config file is required for running the server.
	if opts.ConfigFile == "" {
		return fmt.Errorf("config file is required (-config)")
	}

	return RunServer(ctx, opts)
}

func runTimeProviderMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("time-provider", flag.ExitOnError)
	opts := &TimeProviderOptions{}
	fs.StringVar(&opts.ServerAddr, "server", "127.0.0.1:9443", "Server address")
	fs.StringVar(&opts.ConfigPath, "config", "./time-provider.conf", "Config file path")
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
	fs.StringVar(&opts.ConfigPath, "config", "./time-consumer.conf", "Config file path")
	fs.StringVar(&opts.ProvisionToken, "provision-token", "", "Provision token for initial setup")
	fs.StringVar(&opts.Hostname, "hostname", "time-consumer", "Client hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return RunTimeConsumer(ctx, opts)
}
