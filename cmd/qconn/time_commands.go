package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qexec"
)

// CmdTimeProviderStart starts a time-provider client.
type CmdTimeProviderStart struct {
	ServerAddr     string
	ConfigPath     string
	ProvisionToken string
	Hostname       string

	// OnConnected is called when the client connects but before waiting for authorization.
	OnConnected func(fp qconn.FP)
}

func (c *CmdTimeProviderStart) handler() qconn.Handler {
	return func(ctx context.Context, msg *qconn.Message, w io.Writer, ack qconn.Ack) error {
		if msg.Type != "time" {
			return fmt.Errorf("unknown message type: %s", msg.Type)
		}

		resp := TimeResponse{
			Time:   time.Now(),
			Format: time.RFC3339Nano,
		}
		return cbor.NewEncoder(w).Encode(resp)
	}
}

// registerClientInfo sends the client info update to the server.
// This is used both on initial connection and after reconnection.
func (c *CmdTimeProviderStart) registerClientInfo(ctx context.Context, client *qconn.Client) error {
	updateInfo := qconn.ClientInfoUpdate{
		Devices: []qconn.DeviceInfo{
			{Name: "time-service", Type: "time-provider"},
		},
		MsgTypes:       []string{"time"},
		RequestedRoles: []string{"time-provider"},
	}
	return client.Request(ctx, qconn.System(), "", &updateInfo, nil)
}

// ConnectConfig implements qexec.ClientCommand.
func (c *CmdTimeProviderStart) ConnectConfig() qexec.ConnectConfig {
	hostname := c.Hostname
	if hostname == "" {
		hostname = "time-provider"
	}
	return qexec.ConnectConfig{
		ConfigPath:     c.ConfigPath,
		ServerAddr:     c.ServerAddr,
		ProvisionToken: c.ProvisionToken,
		Hostname:       hostname,
		Handler:        c.handler(),
		OnReconnect:    c.registerClientInfo,
	}
}

// Execute implements qexec.ClientCommand.
func (c *CmdTimeProviderStart) Execute(ctx context.Context, conn *qexec.ConnectResult, responses chan<- any) error {
	// Signal that we're connected and waiting for authorization.
	if c.OnConnected != nil {
		c.OnConnected(conn.Creds.Fingerprint())
	}

	// Advertise capabilities and requested roles before waiting for authorization.
	// This allows admins to see what the client can do and what it's requesting.
	if err := c.registerClientInfo(ctx, conn.Client); err != nil {
		return fmt.Errorf("update client info: %w", err)
	}

	// Wait until authorized before serving requests.
	if err := conn.Client.WaitForConnected(ctx); err != nil {
		return fmt.Errorf("wait for authorization: %w", err)
	}

	// Send ready response.
	responses <- &RespTimeProviderReady{
		Fingerprint: conn.Creds.Fingerprint(),
		Client:      conn.Client,
	}

	// Wait for context cancellation.
	<-ctx.Done()
	return ctx.Err()
}

// CmdTimeConsumerRun runs a time-consumer client that queries the time service.
type CmdTimeConsumerRun struct {
	ServerAddr     string
	ConfigPath     string
	ProvisionToken string
	Hostname       string

	// OnConnected is called when the client connects but before waiting for authorization.
	OnConnected func(fp qconn.FP)
}

// ConnectConfig implements qexec.ClientCommand.
func (c *CmdTimeConsumerRun) ConnectConfig() qexec.ConnectConfig {
	hostname := c.Hostname
	if hostname == "" {
		hostname = "time-consumer"
	}
	return qexec.ConnectConfig{
		ConfigPath:     c.ConfigPath,
		ServerAddr:     c.ServerAddr,
		ProvisionToken: c.ProvisionToken,
		Hostname:       hostname,
	}
}

// Execute implements qexec.ClientCommand.
func (c *CmdTimeConsumerRun) Execute(ctx context.Context, conn *qexec.ConnectResult, responses chan<- any) error {
	// Signal that we're connected and waiting for authorization.
	if c.OnConnected != nil {
		c.OnConnected(conn.Creds.Fingerprint())
	}

	// Advertise requested roles before waiting for authorization.
	updateInfo := qconn.ClientInfoUpdate{
		RequestedRoles: []string{"time-consumer"},
	}
	if err := conn.Client.Request(ctx, qconn.System(), "", &updateInfo, nil); err != nil {
		return fmt.Errorf("update client info: %w", err)
	}

	// Wait until authorized before making requests.
	if err := conn.Client.WaitForConnected(ctx); err != nil {
		return fmt.Errorf("wait for authorization: %w", err)
	}

	// Query time service by device type.
	target := qconn.Target{DeviceType: "time-provider"}

	var resp TimeResponse
	req := TimeRequest{}
	if err := conn.Client.Request(ctx, target, "time-consumer", &req, &resp); err != nil {
		return fmt.Errorf("request time: %w", err)
	}

	responses <- &RespTimeResult{Time: resp.Time}
	return nil
}
