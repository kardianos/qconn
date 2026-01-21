package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn"
)

// TimeProviderOptions configures the time-provider mode.
type TimeProviderOptions struct {
	ServerAddr     string
	CredentialsDir string
	ProvisionToken string
	Hostname       string
}

// TimeResponse is returned by the time endpoint.
type TimeResponse struct {
	Time   time.Time `cbor:"time"`
	Format string    `cbor:"format"`
}

// RunTimeProvider starts a client that provides a time endpoint.
// It blocks until the context is cancelled or an error occurs.
func RunTimeProvider(ctx context.Context, opts *TimeProviderOptions) error {
	return RunTimeProviderWithClient(ctx, opts, nil)
}

// RunTimeProviderWithClient starts a time provider and optionally returns the client.
func RunTimeProviderWithClient(ctx context.Context, opts *TimeProviderOptions, clientCh chan<- *qconn.Client) error {
	hostname := opts.Hostname
	if hostname == "" {
		hostname = "time-provider"
	}

	// Create credential store.
	store, err := qconn.NewFileCredentialStore(qconn.ClientStoreConfig{
		Dir:            opts.CredentialsDir,
		Hostname:       hostname,
		ProvisionToken: opts.ProvisionToken,
	})
	if err != nil {
		return fmt.Errorf("create credential store: %w", err)
	}
	defer store.Close()

	// Create time handler.
	handler := func(ctx context.Context, msg *qconn.Message, w io.Writer, ack qconn.Ack) error {
		if msg.Type != "time" {
			return fmt.Errorf("unknown message type: %s", msg.Type)
		}

		resp := TimeResponse{
			Time:   time.Now(),
			Format: time.RFC3339Nano,
		}
		return cbor.NewEncoder(w).Encode(resp)
	}

	// Connect to server.
	client, err := qconn.NewClient(ctx, qconn.ClientOpt{
		ServerAddr: opts.ServerAddr,
		Auth:       store,
		Handler:    handler,
	})
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer client.Close()

	fmt.Printf("Time provider connected as %s (FP: %s)\n", hostname, store.Fingerprint())

	// Register as a time-provider device type so clients can route by type.
	updateInfo := qconn.ClientInfoUpdate{
		Devices: []qconn.DeviceInfo{
			{Name: "time-service", Type: "time-provider"},
		},
		MsgTypes: []string{"time"},
	}
	if err := client.Request(ctx, qconn.System(), "update-client-info", "", &updateInfo, nil); err != nil {
		return fmt.Errorf("register device: %w", err)
	}
	fmt.Println("Registered as time-provider device")

	// Send client if channel provided.
	if clientCh != nil {
		clientCh <- client
	}

	// Wait for context cancellation.
	<-ctx.Done()
	return ctx.Err()
}
