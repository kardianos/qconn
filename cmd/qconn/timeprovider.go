package main

import (
	"context"
	"fmt"

	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qexec"
)

// TimeProviderOptions configures the time-provider mode.
type TimeProviderOptions struct {
	ServerAddr     string
	ConfigPath     string
	ProvisionToken string
	Hostname       string

	// OnConnected is called when the client connects but before waiting for authorization.
	// This allows callers to know when the client is ready to be approved.
	OnConnected func(fp qconn.FP)
}

// RunTimeProvider starts a client that provides a time endpoint.
// It blocks until the context is cancelled or an error occurs.
func RunTimeProvider(ctx context.Context, opts *TimeProviderOptions) error {
	return RunTimeProviderWithClient(ctx, opts, nil)
}

// RunTimeProviderWithClient starts a time provider and optionally returns the client.
func RunTimeProviderWithClient(ctx context.Context, opts *TimeProviderOptions, clientCh chan<- *qconn.Client) error {
	cmd := &CmdTimeProviderStart{
		ServerAddr:     opts.ServerAddr,
		ConfigPath:     opts.ConfigPath,
		ProvisionToken: opts.ProvisionToken,
		Hostname:       opts.Hostname,
		OnConnected:    opts.OnConnected,
	}

	responses := make(chan any)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(ctx, cmd, responses)
	}()

	for resp := range responses {
		switch r := resp.(type) {
		case *RespTimeProviderReady:
			fmt.Printf("Time provider connected as %s (FP: %s)\n", opts.Hostname, r.Fingerprint)
			fmt.Println("Authorized")
			fmt.Println("Registered as time-provider device")
			if clientCh != nil {
				clientCh <- r.Client
			}
		}
	}

	return <-errCh
}
