package qconn

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
)

// Test request/response types for the generic Handle and Request functions.
type testHelperReq struct {
	Value string `cbor:"value"`
}

type testHelperResp struct {
	Echo   string `cbor:"echo"`
	Suffix string `cbor:"suffix"`
}

func TestStaticDevices(t *testing.T) {
	ctx := context.Background()

	devices := []qdef.DeviceInfo{
		{ID: "dev1", Name: "Device 1", ServiceType: "printer"},
		{ID: "dev2", Name: "Device 2", ServiceType: "scanner"},
	}

	provider := StaticDevices(devices...)

	// Should always return the same devices.
	got := provider.Devices(ctx)
	assertEqual(t, len(devices), len(got))
	for i, d := range got {
		assertEqual(t, devices[i].ID, d.ID)
		assertEqual(t, devices[i].Name, d.Name)
		assertEqual(t, devices[i].ServiceType, d.ServiceType)
	}

	// Call again - should be identical.
	got2 := provider.Devices(ctx)
	assertEqual(t, len(devices), len(got2))
}

func TestTimerDevices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Setup server.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		ProvisionTokens: []string{testProvisionToken},
		Auth:            authManager,
	})
	assertNoError(t, err)

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// Setup client.
	id := qdef.Identity{Hostname: testClientHostname}
	credStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: id,
		Token:    testProvisionToken,
	}

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	clientObs := qmock.NewTestObserver(ctx, t)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        clientObs,
	})

	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// Wait for connection.
	if !waitForState(t, clientObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("client did not connect in time")
	}

	// Track how many times the timer function is called.
	var callCount atomic.Int32
	deviceFn := func(ctx context.Context) []qdef.DeviceInfo {
		count := callCount.Add(1)
		return []qdef.DeviceInfo{
			{ID: "timer-dev", Name: "Timer Device", ServiceType: "test"},
			{ID: "count", Name: string(rune('0' + count)), ServiceType: "counter"},
		}
	}

	// Create timer provider with short interval.
	provider, stopTimer := TimerDevices(ctx, client, 100*time.Millisecond, deviceFn)
	defer stopTimer()

	// Verify initial devices from provider.
	devices := provider.Devices(ctx)
	assertEqual(t, 2, len(devices))
	assertEqual(t, "timer-dev", devices[0].ID)

	// Wait for timer to fire a few times.
	time.Sleep(350 * time.Millisecond)

	// Should have been called multiple times by the timer.
	count := callCount.Load()
	if count < 2 {
		t.Errorf("expected timer to fire at least 2 times, got %d", count)
	}
	t.Logf("Timer fired %d times", count)

	// Stop the timer and verify it stops.
	stopTimer()
	countAfterStop := callCount.Load()
	time.Sleep(200 * time.Millisecond)
	countFinal := callCount.Load()
	if countFinal != countAfterStop {
		t.Errorf("timer should have stopped, but call count changed from %d to %d", countAfterStop, countFinal)
	}
}

func TestGenericHandleAndRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision both clients to avoid rate limiting.
	// Note: roles are passed as variadic args to IssueClientCertificate, not from the identity.
	providerID := qdef.Identity{Hostname: "provider-client"}
	providerCertPEM, providerKeyPEM, err := authManager.IssueClientCertificate(&providerID, "test-role")
	assertNoError(t, err)

	requesterID := qdef.Identity{Hostname: "requester-client"}
	requesterCertPEM, requesterKeyPEM, err := authManager.IssueClientCertificate(&requesterID, "test-role")
	assertNoError(t, err)

	// Authorize both clients.
	err = authManager.SetStatus(providerID, qdef.StatusAuthorized)
	assertNoError(t, err)
	err = authManager.SetStatus(requesterID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// Setup server.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		Auth: authManager,
	})
	assertNoError(t, err)

	// Configure role to allow the test-echo service.
	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	// Setup provider client (handles requests).
	providerStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: providerID,
	}
	err = providerStore.SaveCredentials(providerCertPEM, providerKeyPEM)
	assertNoError(t, err)

	providerObs := qmock.NewTestObserver(ctx, t)

	providerClient := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		ClientHostname:  "provider-client",
		Roles:           []string{"test-role"},
		CredentialStore: providerStore,
		Resolver:        resolver,
		Observer:        providerObs,
	})

	// Register handler using the generic Handle function.
	Handle(providerClient, "test-echo", func(ctx context.Context, id qdef.Identity, req *testHelperReq) (*testHelperResp, error) {
		return &testHelperResp{
			Echo:   req.Value,
			Suffix: "-handled",
		}, nil
	})

	err = providerClient.Connect(ctx)
	assertNoError(t, err)
	defer providerClient.Close()

	// Wait for provider to connect.
	if !waitForState(t, providerObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("provider client did not connect in time")
	}

	// Set devices so the provider is discoverable.
	// TriggerUpdateDevices will transition to Authorized state on success.
	providerClient.SetDevices([]qdef.DeviceInfo{
		{ID: "echo-device", Name: "Echo Device", ServiceType: "test-echo"},
	})
	err = providerClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)
	t.Log("Provider devices registered")

	// Get the provider's fingerprint for addressing.
	provisionedID, _ := providerStore.GetIdentity()
	providerFP := provisionedID.Fingerprint

	// Setup requester client.
	requesterStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: requesterID,
	}
	err = requesterStore.SaveCredentials(requesterCertPEM, requesterKeyPEM)
	assertNoError(t, err)

	requesterObs := qmock.NewTestObserver(ctx, t)

	requesterClient := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		ClientHostname:  "requester-client",
		Roles:           []string{"test-role"},
		CredentialStore: requesterStore,
		Resolver:        resolver,
		Observer:        requesterObs,
	})

	err = requesterClient.Connect(ctx)
	assertNoError(t, err)
	defer requesterClient.Close()

	// Wait for requester to connect.
	if !waitForState(t, requesterObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("requester client did not connect in time")
	}

	// Trigger device update to confirm authorization.
	err = requesterClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)
	t.Log("Requester connected and authorized")

	// Use the generic Request function to send a typed request.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Machine: providerFP,
		Type:    "test-echo",
		Device:  "echo-device",
	}

	req := &testHelperReq{Value: "hello"}
	resp, err := Request[testHelperReq, testHelperResp](requesterClient, ctx, target, req)
	assertNoError(t, err)
	assertNotNil(t, resp)

	assertEqual(t, "hello", resp.Echo)
	assertEqual(t, "-handled", resp.Suffix)

	t.Logf("Request successful: echo=%q suffix=%q", resp.Echo, resp.Suffix)
}
