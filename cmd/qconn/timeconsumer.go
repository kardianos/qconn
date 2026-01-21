package main

import (
	"context"
	"fmt"
	"time"

	"github.com/kardianos/qconn"
)

// TimeConsumerOptions configures the time-consumer mode.
type TimeConsumerOptions struct {
	ServerAddr     string
	CredentialsDir string
	ProvisionToken string
	Hostname       string
}

// RunTimeConsumer starts a client that consumes the time endpoint.
// It queries the time service and prints the result.
func RunTimeConsumer(ctx context.Context, opts *TimeConsumerOptions) error {
	result, err := RunTimeConsumerWithResult(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Printf("Server time: %s\n", result.Time.Format(time.RFC3339Nano))
	return nil
}

// TimeConsumerResult contains the result of querying the time service.
type TimeConsumerResult struct {
	Time time.Time
}

// RunTimeConsumerWithResult queries the time service and returns the result.
func RunTimeConsumerWithResult(ctx context.Context, opts *TimeConsumerOptions) (*TimeConsumerResult, error) {
	hostname := opts.Hostname
	if hostname == "" {
		hostname = "time-consumer"
	}

	// Create credential store.
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

	fmt.Printf("Time consumer connected as %s (FP: %s)\n", hostname, store.Fingerprint())

	// Query time service by device type.
	// The server will route to any client that provides this device type.
	target := qconn.Target{DeviceType: "time-provider"}

	var resp TimeResponse
	// Specify the client's role for RBAC authorization.
	if err := client.Request(ctx, target, "time", "time-consumer", nil, &resp); err != nil {
		return nil, fmt.Errorf("request time: %w", err)
	}

	return &TimeConsumerResult{Time: resp.Time}, nil
}
