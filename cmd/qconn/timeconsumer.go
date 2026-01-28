package main

import (
	"context"
	"fmt"
	"time"

	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qexec"
)

// TimeConsumerOptions configures the time-consumer mode.
type TimeConsumerOptions struct {
	ServerAddr     string
	ConfigPath     string
	ProvisionToken string
	Hostname       string

	// OnConnected is called when the client connects but before waiting for authorization.
	// This allows callers to know when the client is ready to be approved.
	OnConnected func(fp qconn.FP)
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
	cmd := &CmdTimeConsumerRun{
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

	var result *TimeConsumerResult
	for resp := range responses {
		switch r := resp.(type) {
		case *RespTimeResult:
			result = &TimeConsumerResult{Time: r.Time}
		}
	}

	err := <-errCh
	if err != nil {
		return nil, err
	}
	return result, nil
}
