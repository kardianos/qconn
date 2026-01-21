package qconn

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testClient represents a client in the test.
type testClient struct {
	*Client
	hostname string
	fp       FP
	creds    *MemoryCredentialStore
}

// authRBACTest defines a comprehensive test case for auth and RBAC.
type authRBACTest struct {
	Name string

	// RBAC configuration - if nil, no RBAC is configured.
	Roles map[string]*RoleConfig

	// Clients to create. Order matters for setup sequence.
	Clients []testClientSetup

	// Requests to execute in order.
	Requests []testRequest
}

// testClientSetup defines how to set up a client.
type testClientSetup struct {
	Hostname string

	// Authentication method (exactly one should be true).
	UseProvision bool // Use provisioning token to get cert.
	UseSelfAuth  bool // After connect, call self-authorize with auth token.

	// HasHandler enables the client to receive client-to-client messages.
	HasHandler bool

	// NeedsAdminAuth - after connect, an admin authorizes this client (for C2C).
	// Uses admin/client/auth to change state to StateConnected.
	NeedsAdminAuth bool

	// RolesToAssign - after client is connected, an admin assigns these roles.
	// If NeedsAdminAuth is also true, roles are assigned during authorization.
	// Requires another client with admin access to already be set up.
	RolesToAssign []string
}

// testRequest defines a request to make.
type testRequest struct {
	From   string // Client hostname that sends the request.
	Target string // "$system" for system, or client hostname.

	MsgType string // Message type (e.g., "admin/client/list", "echo").
	Role    string // Role to claim (for RBAC). Empty = no role.

	// Expected outcome.
	ExpectSuccess bool
	ErrorContains string // If not empty, error must contain this string.
}

// echoPayload is used for client-to-client echo tests.
type echoPayload struct {
	Message string `cbor:"message"`
}

var authRBACTests = []authRBACTest{
	// ========== System Target - Non-Admin Messages ==========
	{
		Name: "NonAdmin_System_Provisioned_Allow",
		Clients: []testClientSetup{
			{Hostname: "client-a", UseProvision: true},
		},
		Requests: []testRequest{
			{From: "client-a", Target: "$system", MsgType: "update-client-info", ExpectSuccess: true},
		},
	},
	{
		Name: "NonAdmin_System_SelfAuth_Allow",
		Clients: []testClientSetup{
			{Hostname: "client-a", UseProvision: true, UseSelfAuth: true},
		},
		Requests: []testRequest{
			{From: "client-a", Target: "$system", MsgType: "update-client-info", ExpectSuccess: true},
		},
	},

	// ========== System Target - Admin Messages ==========
	{
		Name: "Admin_NoRBAC_NoTempAuth_Deny",
		// No RBAC configured, provisioned client without temp auth.
		Clients: []testClientSetup{
			{Hostname: "client-a", UseProvision: true},
		},
		Requests: []testRequest{
			{From: "client-a", Target: "$system", MsgType: "admin/client/list", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},
	{
		Name: "Admin_TempAuth_Allow",
		// Client self-authorizes to get temp auth.
		Clients: []testClientSetup{
			{Hostname: "client-a", UseProvision: true, UseSelfAuth: true},
		},
		Requests: []testRequest{
			{From: "client-a", Target: "$system", MsgType: "admin/client/list", ExpectSuccess: true},
		},
	},
	{
		Name: "Admin_RBAC_WithRole_Allow",
		Roles: map[string]*RoleConfig{
			"admin": {Submit: []string{"admin/client/list", "admin/client/auth", "admin/client/set-roles"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin-client", UseProvision: true, UseSelfAuth: true},
			{Hostname: "worker-client", UseProvision: true, RolesToAssign: []string{"admin"}},
		},
		Requests: []testRequest{
			// Worker with admin role can call admin messages.
			{From: "worker-client", Target: "$system", MsgType: "admin/client/list", Role: "admin", ExpectSuccess: true},
		},
	},
	{
		Name: "Admin_RBAC_WrongRole_Deny",
		Roles: map[string]*RoleConfig{
			"admin":  {Submit: []string{"admin/client/list"}},
			"worker": {Submit: []string{"echo"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin-client", UseProvision: true, UseSelfAuth: true},
			{Hostname: "worker-client", UseProvision: true, RolesToAssign: []string{"worker"}},
		},
		Requests: []testRequest{
			// Worker role can't submit admin messages.
			{From: "worker-client", Target: "$system", MsgType: "admin/client/list", Role: "worker", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},
	{
		Name: "Admin_RBAC_NoRoleAssigned_Deny",
		Roles: map[string]*RoleConfig{
			"admin": {Submit: []string{"admin/client/list"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin-client", UseProvision: true, UseSelfAuth: true},
			{Hostname: "worker-client", UseProvision: true}, // No roles assigned.
		},
		Requests: []testRequest{
			// Client claims admin role but doesn't have it assigned.
			{From: "worker-client", Target: "$system", MsgType: "admin/client/list", Role: "admin", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},
	{
		Name: "Admin_RBAC_EmptyRole_Deny",
		Roles: map[string]*RoleConfig{
			"admin": {Submit: []string{"admin/client/list"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin-client", UseProvision: true, UseSelfAuth: true},
			{Hostname: "worker-client", UseProvision: true, RolesToAssign: []string{"admin"}},
		},
		Requests: []testRequest{
			// Client has admin role but doesn't claim it in request.
			{From: "worker-client", Target: "$system", MsgType: "admin/client/list", Role: "", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},

	// ========== Client-to-Client - No RBAC ==========
	{
		Name: "C2C_NoRBAC_Allow",
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "client-a", UseProvision: true, NeedsAdminAuth: true},
			{Hostname: "client-b", UseProvision: true, NeedsAdminAuth: true, HasHandler: true},
		},
		Requests: []testRequest{
			{From: "client-a", Target: "client-b", MsgType: "echo", ExpectSuccess: true},
		},
	},
	{
		Name: "C2C_NoRBAC_TargetNotConnected_Deny",
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "client-a", UseProvision: true, NeedsAdminAuth: true},
		},
		Requests: []testRequest{
			{From: "client-a", Target: "nonexistent", MsgType: "echo", ExpectSuccess: false, ErrorContains: "not connected"},
		},
	},

	// ========== Client-to-Client - With RBAC ==========
	{
		Name: "C2C_RBAC_ValidRoles_Allow",
		Roles: map[string]*RoleConfig{
			"controller": {Submit: []string{"print", "scan"}},
			"printer":    {Provide: []string{"print", "scan"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "controller", UseProvision: true, NeedsAdminAuth: true, RolesToAssign: []string{"controller"}},
			{Hostname: "printer", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"printer"}},
		},
		Requests: []testRequest{
			{From: "controller", Target: "printer", MsgType: "print", Role: "controller", ExpectSuccess: true},
		},
	},
	{
		Name: "C2C_RBAC_RoleCantSubmit_Deny",
		Roles: map[string]*RoleConfig{
			"controller": {Submit: []string{"status"}}, // Can only submit "status", not "print".
			"printer":    {Provide: []string{"print"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "controller", UseProvision: true, NeedsAdminAuth: true, RolesToAssign: []string{"controller"}},
			{Hostname: "printer", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"printer"}},
		},
		Requests: []testRequest{
			{From: "controller", Target: "printer", MsgType: "print", Role: "controller", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},
	{
		Name: "C2C_RBAC_TargetCantProvide_Deny",
		Roles: map[string]*RoleConfig{
			"controller": {Submit: []string{"print"}},
			"printer":    {Provide: []string{"scan"}}, // Can only provide "scan", not "print".
		},
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "controller", UseProvision: true, NeedsAdminAuth: true, RolesToAssign: []string{"controller"}},
			{Hostname: "printer", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"printer"}},
		},
		Requests: []testRequest{
			{From: "controller", Target: "printer", MsgType: "print", Role: "controller", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},
	{
		Name: "C2C_RBAC_OriginatorNoRole_Deny",
		Roles: map[string]*RoleConfig{
			"controller": {Submit: []string{"print"}},
			"printer":    {Provide: []string{"print"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "controller", UseProvision: true, NeedsAdminAuth: true}, // Auth'd but no roles assigned.
			{Hostname: "printer", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"printer"}},
		},
		Requests: []testRequest{
			{From: "controller", Target: "printer", MsgType: "print", Role: "controller", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},
	{
		Name: "C2C_RBAC_EmptyRole_Deny",
		Roles: map[string]*RoleConfig{
			"controller": {Submit: []string{"print"}},
			"printer":    {Provide: []string{"print"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "controller", UseProvision: true, NeedsAdminAuth: true, RolesToAssign: []string{"controller"}},
			{Hostname: "printer", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"printer"}},
		},
		Requests: []testRequest{
			{From: "controller", Target: "printer", MsgType: "print", Role: "", ExpectSuccess: false, ErrorContains: "not allowed"},
		},
	},

	// ========== Multi-Role Scenarios ==========
	{
		Name: "C2C_RBAC_MultiRole_TargetHasMultiple_Allow",
		Roles: map[string]*RoleConfig{
			"sender":       {Submit: []string{"task"}},
			"worker-type1": {Provide: []string{"task"}},
			"worker-type2": {Provide: []string{"task"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "sender", UseProvision: true, NeedsAdminAuth: true, RolesToAssign: []string{"sender"}},
			{Hostname: "worker", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"worker-type1", "worker-type2"}},
		},
		Requests: []testRequest{
			{From: "sender", Target: "worker", MsgType: "task", Role: "sender", ExpectSuccess: true},
		},
	},
	{
		Name: "C2C_RBAC_Bidirectional_Allow",
		Roles: map[string]*RoleConfig{
			"peer": {Submit: []string{"ping", "pong"}, Provide: []string{"ping", "pong"}},
		},
		Clients: []testClientSetup{
			{Hostname: "admin", UseProvision: true, UseSelfAuth: true},
			{Hostname: "peer-a", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"peer"}},
			{Hostname: "peer-b", UseProvision: true, NeedsAdminAuth: true, HasHandler: true, RolesToAssign: []string{"peer"}},
		},
		Requests: []testRequest{
			{From: "peer-a", Target: "peer-b", MsgType: "ping", Role: "peer", ExpectSuccess: true},
			{From: "peer-b", Target: "peer-a", MsgType: "pong", Role: "peer", ExpectSuccess: true},
		},
	},
}

func TestAuthRBAC(t *testing.T) {
	for _, tc := range authRBACTests {
		t.Run(tc.Name, func(t *testing.T) {
			runAuthRBACTest(t, tc)
		})
	}
}

func runAuthRBACTest(t *testing.T, tc authRBACTest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create temp directory for bbolt database.
	tempDir, err := os.MkdirTemp("", "qconn-rbac-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Shared tokens.
	provisionToken := "test-provision-token"
	authToken := "" // Will be created if needed.

	// Create BoltAuthManager.
	authCfg := BoltAuthConfig{
		DBPath:          filepath.Join(tempDir, "auth.db"),
		ServerHostname:  "localhost",
		ProvisionTokens: []string{provisionToken},
		Roles:           tc.Roles,
	}
	auth, isNew, err := NewBoltAuthManager(authCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	// Create auth token if any client needs self-auth.
	for _, cs := range tc.Clients {
		if cs.UseSelfAuth {
			if authToken == "" {
				authToken, err = auth.CreateAuthToken()
				if err != nil {
					t.Fatalf("CreateAuthToken failed: %v", err)
				}
			}
			break
		}
	}
	_ = isNew

	// Create and start server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Echo handler for clients that receive messages.
	echoHandler := func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
		_, err := w.Write(msg.Payload)
		return err
	}

	// Create clients.
	clients := make(map[string]*testClient)

	for _, cs := range tc.Clients {
		creds := NewMemoryCredentialStore(provisionToken, cs.Hostname)

		var handler Handler
		if cs.HasHandler {
			handler = echoHandler
		}

		client, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       creds,
			Handler:    handler,
		})
		if err != nil {
			t.Fatalf("client %s failed to connect: %v", cs.Hostname, err)
		}
		defer func(c *Client) { _ = c.Close() }(client)

		// Register client info - this is a normal client operation after connecting.
		// It also ensures the server has fully registered the connection.
		if err := client.Request(ctx, System(), "update-client-info", "", &ClientInfoUpdate{}, nil); err != nil {
			t.Fatalf("client %s update-client-info failed: %v", cs.Hostname, err)
		}

		// Get fingerprint from cert.
		certPEM := creds.CertPEM()
		block, _ := pem.Decode(certPEM)
		cert, _ := x509.ParseCertificate(block.Bytes)
		fp := FingerprintOf(cert)

		clients[cs.Hostname] = &testClient{
			Client:   client,
			hostname: cs.Hostname,
			fp:       fp,
			creds:    creds,
		}

		// Self-authorize if needed.
		if cs.UseSelfAuth {
			err = client.Request(ctx, System(), "self-authorize", "", &SelfAuthorizeRequest{Token: authToken}, nil)
			if err != nil {
				t.Fatalf("client %s self-authorize failed: %v", cs.Hostname, err)
			}
			// Create new auth token for next client that needs it.
			authToken, err = auth.CreateAuthToken()
			if err != nil {
				t.Fatalf("CreateAuthToken failed: %v", err)
			}
		}

		// Admin-authorize if needed - find an admin client to do this.
		if cs.NeedsAdminAuth || len(cs.RolesToAssign) > 0 {
			var adminClient *testClient
			for _, ac := range clients {
				// Find a client that already did self-auth (has temp auth).
				for _, prevSetup := range tc.Clients {
					if prevSetup.Hostname == ac.hostname && prevSetup.UseSelfAuth {
						adminClient = ac
						break
					}
				}
				if adminClient != nil {
					break
				}
			}
			if adminClient == nil {
				t.Fatalf("no admin client available to authorize %s", cs.Hostname)
			}

			// Authorize client via admin endpoint (sets status and state).
			err = adminClient.Request(ctx, System(), "admin/client/auth", "", &AuthorizeClientRequest{
				FP:    fp,
				Roles: cs.RolesToAssign,
			}, nil)
			if err != nil {
				t.Fatalf("failed to authorize client %s: %v", cs.Hostname, err)
			}
		}
	}

	// Execute requests.
	for i, req := range tc.Requests {
		fromClient, ok := clients[req.From]
		if !ok {
			t.Fatalf("request %d: from client %q not found", i, req.From)
		}

		var target Target
		if req.Target == "$system" {
			target = System()
		} else {
			target = ToMachine(req.Target)
		}

		var err error
		switch req.MsgType {
		case "echo", "print", "scan", "ping", "pong", "task":
			// Client-to-client message.
			var resp echoPayload
			payload := echoPayload{Message: "test"}
			err = fromClient.Request(ctx, target, req.MsgType, req.Role, &payload, &resp)
		case "update-client-info":
			// System non-admin message.
			err = fromClient.Request(ctx, target, req.MsgType, "", &ClientInfoUpdate{}, nil)
		case "admin/client/list":
			// Admin message.
			var resp []ClientInfo
			err = fromClient.Request(ctx, target, req.MsgType, req.Role, nil, &resp)
		default:
			t.Fatalf("request %d: unknown msgType %q", i, req.MsgType)
		}

		if req.ExpectSuccess {
			if err != nil {
				t.Errorf("request %d (%s -> %s %s): expected success, got error: %v", i, req.From, req.Target, req.MsgType, err)
			}
		} else {
			if err == nil {
				t.Errorf("request %d (%s -> %s %s): expected error containing %q, got success", i, req.From, req.Target, req.MsgType, req.ErrorContains)
			} else if req.ErrorContains != "" && !strings.Contains(err.Error(), req.ErrorContains) {
				t.Errorf("request %d (%s -> %s %s): expected error containing %q, got: %v", i, req.From, req.Target, req.MsgType, req.ErrorContains, err)
			}
		}
	}
}

// TestRenewalWithFakeTime tests certificate renewal using fake time.
func TestRenewalWithFakeTime(t *testing.T) {
	// Set up fake time and restore after test.
	fakeNow := time.Now()
	cleanup := setFakeTime(&fakeNow)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create temp directory for bbolt database.
	tempDir, err := os.MkdirTemp("", "qconn-renewal-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	provisionToken := "test-provision-token"

	// Configure RBAC roles.
	roles := map[string]*RoleConfig{
		"worker": {Submit: []string{"task"}, Provide: []string{"result"}},
	}

	// Create BoltAuthManager.
	auth, _, err := NewBoltAuthManager(BoltAuthConfig{
		DBPath:          filepath.Join(tempDir, "auth.db"),
		ServerHostname:  "localhost",
		ProvisionTokens: []string{provisionToken},
		Roles:           roles,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	// Create auth token for admin.
	authToken, err := auth.CreateAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	// Create and start server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		_ = server.Serve(ctx, conn)
	}()

	serverAddr := conn.LocalAddr().String()

	// Create admin client - provisions and self-authorizes.
	adminCreds := NewMemoryCredentialStore(provisionToken, "admin")
	adminClient, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       adminCreds,
	})
	if err != nil {
		t.Fatalf("admin client failed: %v", err)
	}
	defer func() { _ = adminClient.Close() }()

	// Register and self-authorize admin.
	if err := adminClient.Request(ctx, System(), "update-client-info", "", &ClientInfoUpdate{}, nil); err != nil {
		t.Fatalf("admin update-client-info failed: %v", err)
	}
	if err := adminClient.Request(ctx, System(), "self-authorize", "", &SelfAuthorizeRequest{Token: authToken}, nil); err != nil {
		t.Fatalf("admin self-authorize failed: %v", err)
	}

	// Create worker client.
	workerCreds := NewMemoryCredentialStore(provisionToken, "worker")
	workerClient, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       workerCreds,
	})
	if err != nil {
		t.Fatalf("worker client failed: %v", err)
	}

	// Register worker and get its FP.
	if err := workerClient.Request(ctx, System(), "update-client-info", "", &ClientInfoUpdate{}, nil); err != nil {
		t.Fatalf("worker update-client-info failed: %v", err)
	}

	workerCertPEM := workerCreds.CertPEM()
	block, _ := pem.Decode(workerCertPEM)
	workerCert, _ := x509.ParseCertificate(block.Bytes)
	originalFP := FingerprintOf(workerCert)
	originalExpiry := workerCert.NotAfter

	// Admin authorizes worker with role.
	if err := adminClient.Request(ctx, System(), "admin/client/auth", "", &AuthorizeClientRequest{
		FP:    originalFP,
		Roles: []string{"worker"},
	}, nil); err != nil {
		t.Fatalf("admin/client/auth failed: %v", err)
	}

	// Verify worker has the role.
	rec, err := auth.GetClientRecord(originalFP)
	if err != nil {
		t.Fatalf("GetClientRecord failed: %v", err)
	}
	if rec == nil || len(rec.Roles) == 0 || rec.Roles[0] != "worker" {
		t.Fatalf("expected worker role, got: %v", rec)
	}

	t.Logf("Original cert expires at: %v", originalExpiry)
	t.Logf("Original FP: %s", originalFP)

	// === Test 1: Renew certificate ===
	// Create renewal CSR.
	csrPEM, newKeyPEM, err := CreateCSR("worker")
	if err != nil {
		t.Fatalf("CreateCSR failed: %v", err)
	}

	// Send renewal request.
	var renewResp RenewResponse
	if err := workerClient.Request(ctx, System(), "renew", "", &RenewRequest{CSRPEM: csrPEM}, &renewResp); err != nil {
		t.Fatalf("renew request failed: %v", err)
	}

	if len(renewResp.CertPEM) == 0 {
		t.Fatal("renewal returned empty cert")
	}

	// Parse new cert.
	block, _ = pem.Decode(renewResp.CertPEM)
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse renewed cert: %v", err)
	}
	newFP := FingerprintOf(newCert)
	newExpiry := newCert.NotAfter

	t.Logf("New cert expires at: %v", newExpiry)
	t.Logf("New FP: %s", newFP)

	// Verify FP changed (new key = new fingerprint).
	if newFP == originalFP {
		t.Error("expected new FP after renewal, got same FP")
	}

	// === Test 2: Verify roles are preserved after renewal ===
	newRec, err := auth.GetClientRecord(newFP)
	if err != nil {
		t.Fatalf("GetClientRecord for new FP failed: %v", err)
	}
	if newRec == nil {
		t.Fatal("no record found for new FP")
	}
	if len(newRec.Roles) == 0 || newRec.Roles[0] != "worker" {
		t.Errorf("expected worker role preserved, got: %v", newRec.Roles)
	}
	if newRec.Status != StatusAuthenticated {
		t.Errorf("expected StatusAuthenticated, got: %v", newRec.Status)
	}

	t.Log("Roles preserved after renewal: OK")

	// === Test 3: Reconnect with new cert and verify operations work ===
	workerClient.Close()

	// Save new credentials.
	rootCAPEM, _ := auth.RootCertPEM()
	if err := workerCreds.SaveCredentials(renewResp.CertPEM, newKeyPEM, rootCAPEM); err != nil {
		t.Fatalf("SaveCredentials failed: %v", err)
	}

	// Reconnect.
	workerClient, err = NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       workerCreds,
	})
	if err != nil {
		t.Fatalf("reconnect with renewed cert failed: %v", err)
	}
	defer func() { _ = workerClient.Close() }()

	// Register after reconnect.
	if err := workerClient.Request(ctx, System(), "update-client-info", "", &ClientInfoUpdate{}, nil); err != nil {
		t.Fatalf("update-client-info after reconnect failed: %v", err)
	}

	t.Log("Reconnected with renewed cert: OK")

	// === Test 4: Advance time past original expiry - old FP should be expired ===
	// The client record stores ExpiresAt from cert.NotAfter when SetClientStatus is called.
	// GetClientStatus checks if timeNow().After(rec.ExpiresAt) and returns StatusUnknown if expired.
	advancedTime := originalExpiry.Add(time.Hour)
	setFakeTime(&advancedTime)
	t.Logf("Advanced time to: %v (1 hour after original expiry)", advancedTime)

	// Old FP should now return StatusUnknown (expired).
	oldStatus, err := auth.GetClientStatus(originalFP)
	if err != nil {
		t.Fatalf("GetClientStatus for old FP failed: %v", err)
	}
	if oldStatus != StatusUnknown {
		t.Errorf("expected old FP to be StatusUnknown (expired), got: %v", oldStatus)
	}

	t.Log("Old FP expired after time advance: OK")
}
