package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/kardianos/qconn"
)

func TestIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create temp directories.
	tempDir, err := os.MkdirTemp("", "qconn-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Define provision token and roles.
	provisionToken := "integration-test-provision-token"

	// Roles configuration:
	// - admin: can submit admin messages
	// - time-provider: can provide "time" messages
	// - time-consumer: can submit "time" messages
	roles := map[string]*qconn.RoleConfig{
		"admin": {
			Submit: []string{"admin/client/list", "admin/client/auth", "admin/client/revoke"},
		},
		"time-provider": {
			Provide: []string{"time"},
		},
		"time-consumer": {
			Submit: []string{"time"},
		},
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		t.Fatal(err)
	}

	provisionTokensJSON, err := json.Marshal([]string{provisionToken})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Start server
	t.Log("Step 1: Starting server...")
	serverResultCh := make(chan *ServerResult, 1)
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	serverOpts := &ServerOptions{
		ListenAddr:          "127.0.0.1:0",
		DataDir:             tempDir + "/server",
		ProvisionTokensJSON: string(provisionTokensJSON),
		RolesJSON:           string(rolesJSON),
	}

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- RunServerWithResult(serverCtx, serverOpts, serverResultCh)
	}()

	// Wait for server to start.
	var serverResult *ServerResult
	select {
	case serverResult = <-serverResultCh:
		t.Logf("Server started on %s, auth token: %s", serverResult.Addr, serverResult.AuthToken)
	case err := <-serverErrCh:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server startup timeout")
	}

	// 2. Provision and authorize admin client
	t.Log("Step 2: Provisioning and authorizing admin client...")
	adminOpts := &AdminOptions{
		ServerAddr:     serverResult.Addr,
		CredentialsDir: tempDir + "/admin-creds",
		ProvisionToken: provisionToken,
		AuthToken:      serverResult.AuthToken, // Self-authorize immediately
		Command:        "list",
	}

	// First call provisions, self-authorizes, and lists.
	result, err := RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin list failed: %v", err)
	}
	t.Logf("Admin self-authorized, clients: %d", len(result.Clients))

	// Clear auth token - it's single-use.
	adminOpts.AuthToken = ""

	// Find admin in list.
	var adminFP qconn.FP
	for _, c := range result.Clients {
		if c.Hostname == "admin" || c.Status == qconn.StatusAuthenticated {
			adminFP = c.Fingerprint
			t.Logf("Admin FP: %s, Status: %s, Online: %v", c.Fingerprint, c.Status, c.Online)
		}
	}
	if adminFP.IsZero() {
		t.Fatal("Admin not found in client list")
	}

	// 4. Start time-provider (will be unauthenticated)
	t.Log("Step 4: Starting time-provider...")
	providerCtx, providerCancel := context.WithCancel(ctx)
	defer providerCancel()

	providerOpts := &TimeProviderOptions{
		ServerAddr:     serverResult.Addr,
		CredentialsDir: tempDir + "/time-provider-creds",
		ProvisionToken: provisionToken,
		Hostname:       "time-provider",
	}

	providerClientCh := make(chan *qconn.Client, 1)
	providerErrCh := make(chan error, 1)
	go func() {
		providerErrCh <- RunTimeProviderWithClient(providerCtx, providerOpts, providerClientCh)
	}()

	// Wait for provider to connect.
	select {
	case <-providerClientCh:
		t.Log("Time-provider connected")
	case err := <-providerErrCh:
		t.Fatalf("Time-provider failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Time-provider startup timeout")
	}

	// 5. Admin lists clients - should see time-provider as Online, Unauthenticated
	t.Log("Step 5: Admin listing clients...")
	time.Sleep(500 * time.Millisecond) // Let server fully register the client
	adminOpts.Command = "list"
	result, err = RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin list failed: %v", err)
	}
	t.Logf("Total clients in list: %d", len(result.Clients))

	var providerFP qconn.FP
	for _, c := range result.Clients {
		t.Logf("  Client: %s, Hostname: %s, Status: %s, Online: %v", c.Fingerprint, c.Hostname, c.Status, c.Online)
		if c.Hostname == "time-provider" {
			providerFP = c.Fingerprint
			if !c.Online {
				t.Error("Expected time-provider to be Online")
			}
			if c.Status != qconn.StatusUnauthenticated {
				t.Errorf("Expected time-provider Status=Unauthenticated, got %s", c.Status)
			}
		}
	}
	if providerFP.IsZero() {
		t.Fatal("Time-provider not found in client list")
	}

	// 6. Admin approves time-provider with time-provider role
	t.Log("Step 6: Admin approving time-provider...")
	adminOpts.Command = "approve"
	adminOpts.TargetFP = providerFP.String()
	adminOpts.RolesJSON = `["time-provider"]`
	adminOpts.MsgTypesJSON = `["time"]`
	_, err = RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin approve time-provider failed: %v", err)
	}
	t.Log("Time-provider approved")

	// 7. Start time-consumer, get it authorized
	t.Log("Step 7: Starting and authorizing time-consumer...")
	consumerOpts := &TimeConsumerOptions{
		ServerAddr:     serverResult.Addr,
		CredentialsDir: tempDir + "/time-consumer-creds",
		ProvisionToken: provisionToken,
		Hostname:       "time-consumer",
	}

	// First, just connect to provision (will fail at time request since unauthenticated).
	_, err = RunTimeConsumerWithResult(ctx, consumerOpts)
	if err == nil {
		t.Fatal("Expected time-consumer to fail before authorization")
	}
	t.Logf("Time-consumer request failed as expected: %v", err)

	// Find consumer in list and approve it.
	adminOpts.Command = "list"
	result, err = RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin list failed: %v", err)
	}

	var consumerFP qconn.FP
	for _, c := range result.Clients {
		if c.Hostname == "time-consumer" {
			consumerFP = c.Fingerprint
			break
		}
	}
	if consumerFP.IsZero() {
		t.Fatal("Time-consumer not found in client list")
	}

	adminOpts.Command = "approve"
	adminOpts.TargetFP = consumerFP.String()
	adminOpts.RolesJSON = `["time-consumer"]`
	adminOpts.MsgTypesJSON = `[]`
	_, err = RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin approve time-consumer failed: %v", err)
	}
	t.Log("Time-consumer approved")

	// 8. Time-consumer calls time endpoint
	t.Log("Step 8: Time-consumer requesting time...")
	timeResult, err := RunTimeConsumerWithResult(ctx, consumerOpts)
	if err != nil {
		t.Fatalf("Time-consumer request failed: %v", err)
	}
	t.Logf("Time from server: %s", timeResult.Time.Format(time.RFC3339Nano))

	// 9. Stop time-provider
	t.Log("Step 9: Stopping time-provider...")
	providerCancel()
	time.Sleep(200 * time.Millisecond) // Let server process disconnect

	// 10. Admin lists - time-provider should be Offline but still Authenticated
	t.Log("Step 10: Admin listing clients (time-provider should be offline)...")
	adminOpts.Command = "list"
	result, err = RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin list failed: %v", err)
	}

	for _, c := range result.Clients {
		t.Logf("  Client: %s, Hostname: %s, Status: %s, Online: %v", c.Fingerprint, c.Hostname, c.Status, c.Online)
		if c.Hostname == "time-provider" {
			if c.Online {
				t.Error("Expected time-provider to be Offline")
			}
			if c.Status != qconn.StatusAuthenticated {
				t.Errorf("Expected time-provider Status=Authenticated, got %s", c.Status)
			}
		}
	}

	// 11. Admin revokes time-provider
	t.Log("Step 11: Admin revoking time-provider...")
	adminOpts.Command = "revoke"
	adminOpts.TargetFP = providerFP.String()
	_, err = RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin revoke time-provider failed: %v", err)
	}
	t.Log("Time-provider revoked")

	// 12. Try to reconnect time-provider - should be rejected
	t.Log("Step 12: Trying to reconnect revoked time-provider...")
	providerCtx2, providerCancel2 := context.WithCancel(ctx)
	defer providerCancel2()

	providerClientCh2 := make(chan *qconn.Client, 1)
	providerErrCh2 := make(chan error, 1)
	go func() {
		providerErrCh2 <- RunTimeProviderWithClient(providerCtx2, providerOpts, providerClientCh2)
	}()

	// Should fail to connect.
	select {
	case <-providerClientCh2:
		t.Error("Expected revoked time-provider to be rejected, but it connected")
		providerCancel2()
	case err := <-providerErrCh2:
		t.Logf("Revoked time-provider rejected as expected: %v", err)
	case <-time.After(3 * time.Second):
		t.Log("Revoked time-provider timed out (expected)")
		providerCancel2()
	}

	// 13. Admin lists - time-provider should show as Revoked
	t.Log("Step 13: Admin listing clients (time-provider should be revoked)...")
	adminOpts.Command = "list"
	result, err = RunAdminWithResult(ctx, adminOpts)
	if err != nil {
		t.Fatalf("Admin list failed: %v", err)
	}

	for _, c := range result.Clients {
		t.Logf("  Client: %s, Hostname: %s, Status: %s, Online: %v", c.Fingerprint, c.Hostname, c.Status, c.Online)
		if c.Hostname == "time-provider" {
			if c.Online {
				t.Error("Expected time-provider to be Offline")
			}
			if c.Status != qconn.StatusRevoked {
				t.Errorf("Expected time-provider Status=Revoked, got %s", c.Status)
			}
		}
	}

	t.Log("Integration test completed successfully!")
}
