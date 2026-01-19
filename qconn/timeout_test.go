package qconn

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
	"github.com/quic-go/quic-go"
)

// TestResolutionTimeout_MachineNotFound tests that the resolution timeout fires
// when the target machine never connects.
func TestResolutionTimeout_MachineNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision a requester client.
	requesterID := qdef.Identity{Hostname: "requester-client"}
	requesterCertPEM, requesterKeyPEM, err := authManager.IssueClientCertificate(&requesterID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(requesterID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// Setup server with short resolution timeout.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		Auth:              authManager,
		ResolutionTimeout: 200 * time.Millisecond, // Short timeout
		JobTimeout:        5 * time.Second,        // Longer job timeout (shouldn't be reached)
	})
	assertNoError(t, err)

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

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

	// Wait for connection.
	if !waitForState(t, requesterObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("requester client did not connect in time")
	}

	// Authorize client by triggering device update.
	err = requesterClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

	// Create a fake fingerprint for a machine that doesn't exist.
	var nonExistentFP qdef.FP
	for i := range nonExistentFP {
		nonExistentFP[i] = byte(i + 0xAA)
	}

	// Send request to non-existent machine.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Machine: nonExistentFP,
		Type:    "test-echo",
	}

	start := time.Now()
	_, err = requesterClient.Request(ctx, target, "hello", nil)
	elapsed := time.Since(start)

	// Should fail with TargetUnavailableError.
	if err == nil {
		t.Fatal("expected error for non-existent machine")
	}
	t.Logf("Got expected error: %v", err)

	// Should timeout around resolution timeout (200ms), not job timeout (5s).
	if elapsed > 1*time.Second {
		t.Errorf("timeout took too long: %v (expected ~200ms)", elapsed)
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("timeout too fast: %v (expected ~200ms)", elapsed)
	}
	t.Logf("Request timed out in %v", elapsed)
}

// TestResolutionTimeout_NoAck tests that the resolution timeout fires
// when the target machine is found but doesn't send an ack.
// This uses a raw QUIC connection to simulate a misbehaving target that
// receives messages but never responds (no ack, no response).
func TestResolutionTimeout_NoAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision both clients.
	providerID := qdef.Identity{Hostname: "provider-client"}
	providerCertPEM, providerKeyPEM, err := authManager.IssueClientCertificate(&providerID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(providerID, qdef.StatusAuthorized)
	assertNoError(t, err)

	requesterID := qdef.Identity{Hostname: "requester-client"}
	requesterCertPEM, requesterKeyPEM, err := authManager.IssueClientCertificate(&requesterID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(requesterID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// Setup server with short resolution timeout.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		Auth:              authManager,
		ResolutionTimeout: 300 * time.Millisecond, // Short timeout for ack
		JobTimeout:        5 * time.Second,        // Longer job timeout (shouldn't be reached)
	})
	assertNoError(t, err)

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	// Setup provider using raw QUIC - this simulates a misbehaving client
	// that connects, registers devices, but never sends ack or response.
	providerStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: providerID,
	}
	err = providerStore.SaveCredentials(providerCertPEM, providerKeyPEM)
	assertNoError(t, err)

	providerTlsCert, err := providerStore.GetClientCertificate()
	assertNoError(t, err)
	providerRootCAs, err := providerStore.GetRootCAs()
	assertNoError(t, err)

	providerTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{providerTlsCert},
		RootCAs:      providerRootCAs,
		ServerName:   "localhost",
	}

	providerConn, err := quic.DialAddr(ctx, quicAddr, providerTlsConfig, &quic.Config{
		MaxIncomingStreams: 100,
	})
	assertNoError(t, err)
	defer providerConn.CloseWithError(0, "test done")

	// Register devices via device update request.
	providerStream, err := providerConn.OpenStreamSync(ctx)
	assertNoError(t, err)
	providerEnc := cbor.NewEncoder(providerStream)
	providerDec := cbor.NewDecoder(providerStream)

	deviceReq := qdef.DeviceUpdateRequest{
		Hostname: "provider-client",
		Devices: []qdef.DeviceInfo{
			{ID: "echo-device", Name: "Echo Device", ServiceType: "test-echo"},
		},
	}
	deviceMsg := qdef.Message{
		ID: 1,
		Target: qdef.Addr{
			Service: qdef.ServiceSystem,
			Type:    "devices",
		},
		Payload: mustMarshal(deviceReq),
	}
	err = providerEnc.Encode(deviceMsg)
	assertNoError(t, err)

	var deviceResp qdef.Message
	err = providerDec.Decode(&deviceResp)
	assertNoError(t, err)
	if deviceResp.Error != "" {
		t.Fatalf("device update failed: %s", deviceResp.Error)
	}
	providerStream.Close()

	// Get provider fingerprint.
	provisionedID, _ := providerStore.GetIdentity()
	providerFP := provisionedID.Fingerprint

	// Start goroutine to accept incoming streams but never respond (no ack).
	silentAcceptDone := make(chan struct{})
	go func() {
		defer close(silentAcceptDone)
		for {
			stream, err := providerConn.AcceptStream(ctx)
			if err != nil {
				return // Connection closed
			}
			// Read the message but don't send ack or response.
			// Just let the stream hang until deadline.
			var msg qdef.Message
			dec := cbor.NewDecoder(stream)
			_ = dec.Decode(&msg)
			t.Logf("Silent provider received message ID=%d, letting it hang (no ack)", msg.ID)
			// Don't close the stream - let it hang so the server's deadline fires.
		}
	}()
	defer func() {
		providerConn.CloseWithError(0, "test done")
		<-silentAcceptDone
	}()

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

	if !waitForState(t, requesterObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("requester client did not connect in time")
	}

	err = requesterClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

	// Send request to provider that won't ack.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Machine: providerFP,
		Type:    "test-echo",
		Device:  "echo-device",
	}

	start := time.Now()
	_, err = requesterClient.Request(ctx, target, "hello", nil)
	elapsed := time.Since(start)

	// Should fail.
	if err == nil {
		t.Fatal("expected error for no-ack scenario")
	}
	t.Logf("Got expected error: %v", err)

	// Should timeout around resolution timeout (300ms), not job timeout (5s).
	// Allow some margin for network latency.
	if elapsed > 1*time.Second {
		t.Errorf("timeout took too long: %v (expected ~300ms)", elapsed)
	}
	if elapsed < 200*time.Millisecond {
		t.Errorf("timeout too fast: %v (expected ~300ms)", elapsed)
	}
	t.Logf("Request timed out in %v (no ack)", elapsed)
}

// TestJobTimeout_SlowResponse tests that the job timeout fires when
// the target acks but takes too long to respond.
func TestJobTimeout_SlowResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision both clients.
	providerID := qdef.Identity{Hostname: "provider-client"}
	providerCertPEM, providerKeyPEM, err := authManager.IssueClientCertificate(&providerID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(providerID, qdef.StatusAuthorized)
	assertNoError(t, err)

	requesterID := qdef.Identity{Hostname: "requester-client"}
	requesterCertPEM, requesterKeyPEM, err := authManager.IssueClientCertificate(&requesterID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(requesterID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// Setup server with longer resolution timeout but short job timeout.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		Auth:              authManager,
		ResolutionTimeout: 5 * time.Second,        // Long resolution timeout
		JobTimeout:        300 * time.Millisecond, // Short job timeout
	})
	assertNoError(t, err)

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	// Setup provider client with a slow handler.
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

	// Handler that will cause ack to be sent (via client's acceptLoop),
	// but then takes a long time to respond.
	Handle(providerClient, "test-echo", func(ctx context.Context, id qdef.Identity, req *string) (*string, error) {
		// Ack is sent automatically before this handler is called.
		// Now delay the response longer than job timeout.
		select {
		case <-time.After(2 * time.Second):
			resp := "too late"
			return &resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	err = providerClient.Connect(ctx)
	assertNoError(t, err)
	defer providerClient.Close()

	if !waitForState(t, providerObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("provider client did not connect in time")
	}

	providerClient.SetDevices([]qdef.DeviceInfo{
		{ID: "echo-device", Name: "Echo Device", ServiceType: "test-echo"},
	})
	err = providerClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

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

	if !waitForState(t, requesterObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("requester client did not connect in time")
	}

	err = requesterClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

	// Send request to provider with slow handler.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Machine: providerFP,
		Type:    "test-echo",
		Device:  "echo-device",
	}

	start := time.Now()
	_, err = requesterClient.Request(ctx, target, "hello", nil)
	elapsed := time.Since(start)

	// Should fail.
	if err == nil {
		t.Fatal("expected error for slow response scenario")
	}
	t.Logf("Got expected error: %v", err)

	// Should timeout around job timeout (300ms), not handler delay (2s).
	// Allow margin for ack round-trip.
	if elapsed > 1*time.Second {
		t.Errorf("timeout took too long: %v (expected ~300ms after ack)", elapsed)
	}
	if elapsed < 200*time.Millisecond {
		t.Errorf("timeout too fast: %v (expected ~300ms after ack)", elapsed)
	}
	t.Logf("Request timed out in %v (slow response after ack)", elapsed)
}

// TestTimeout_Success tests that requests complete successfully when
// both ack and response arrive within their respective timeouts.
func TestTimeout_Success(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision both clients.
	providerID := qdef.Identity{Hostname: "provider-client"}
	providerCertPEM, providerKeyPEM, err := authManager.IssueClientCertificate(&providerID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(providerID, qdef.StatusAuthorized)
	assertNoError(t, err)

	requesterID := qdef.Identity{Hostname: "requester-client"}
	requesterCertPEM, requesterKeyPEM, err := authManager.IssueClientCertificate(&requesterID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(requesterID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// Setup server with reasonable timeouts.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		Auth:              authManager,
		ResolutionTimeout: 5 * time.Second,
		JobTimeout:        5 * time.Second,
	})
	assertNoError(t, err)

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	// Setup provider client with a fast handler.
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

	Handle(providerClient, "test-echo", func(ctx context.Context, id qdef.Identity, req *string) (*string, error) {
		// Fast response.
		resp := "echo: " + *req
		return &resp, nil
	})

	err = providerClient.Connect(ctx)
	assertNoError(t, err)
	defer providerClient.Close()

	if !waitForState(t, providerObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("provider client did not connect in time")
	}

	providerClient.SetDevices([]qdef.DeviceInfo{
		{ID: "echo-device", Name: "Echo Device", ServiceType: "test-echo"},
	})
	err = providerClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

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

	if !waitForState(t, requesterObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("requester client did not connect in time")
	}

	err = requesterClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

	// Send request to provider.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Machine: providerFP,
		Type:    "test-echo",
		Device:  "echo-device",
	}

	var response string
	start := time.Now()
	_, err = requesterClient.Request(ctx, target, "hello", &response)
	elapsed := time.Since(start)

	// Should succeed.
	assertNoError(t, err)
	assertEqual(t, "echo: hello", response)
	t.Logf("Request completed in %v with response: %q", elapsed, response)
}

// TestMessageObserver tests that the MessageObserver is called with correct state transitions.
func TestMessageObserver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision both clients.
	providerID := qdef.Identity{Hostname: "provider-client"}
	providerCertPEM, providerKeyPEM, err := authManager.IssueClientCertificate(&providerID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(providerID, qdef.StatusAuthorized)
	assertNoError(t, err)

	requesterID := qdef.Identity{Hostname: "requester-client"}
	requesterCertPEM, requesterKeyPEM, err := authManager.IssueClientCertificate(&requesterID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(requesterID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// Create message observer to track state transitions.
	type observedMessage struct {
		lastState qdef.MessageState
		duration  time.Duration
		err       error
	}
	observed := make(chan observedMessage, 10)

	observer := &testMessageObserver{
		onComplete: func(src qdef.Identity, dest qdef.Addr, msgID qdef.MessageID, lastState qdef.MessageState, duration time.Duration, err error) {
			observed <- observedMessage{lastState: lastState, duration: duration, err: err}
		},
	}

	// Setup server with message observer.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		Auth:              authManager,
		ResolutionTimeout: 5 * time.Second,
		JobTimeout:        5 * time.Second,
		MessageObserver:   observer,
	})
	assertNoError(t, err)

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	// Setup provider client.
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

	Handle(providerClient, "test-echo", func(ctx context.Context, id qdef.Identity, req *string) (*string, error) {
		resp := "observed: " + *req
		return &resp, nil
	})

	err = providerClient.Connect(ctx)
	assertNoError(t, err)
	defer providerClient.Close()

	if !waitForState(t, providerObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("provider client did not connect in time")
	}

	providerClient.SetDevices([]qdef.DeviceInfo{
		{ID: "echo-device", Name: "Echo Device", ServiceType: "test-echo"},
	})
	err = providerClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

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

	if !waitForState(t, requesterObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("requester client did not connect in time")
	}

	err = requesterClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

	// Send request to provider.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Machine: providerFP,
		Type:    "test-echo",
		Device:  "echo-device",
	}

	var response string
	_, err = requesterClient.Request(ctx, target, "hello", &response)
	assertNoError(t, err)
	assertEqual(t, "observed: hello", response)

	// Check observer was called.
	select {
	case obs := <-observed:
		// Should have reached ForwardedResponse state on success.
		if obs.lastState != qdef.MsgStateForwardedResponse {
			t.Errorf("expected lastState=%v, got %v", qdef.MsgStateForwardedResponse, obs.lastState)
		}
		if obs.err != nil {
			t.Errorf("expected no error, got %v", obs.err)
		}
		t.Logf("Observer received: state=%v, duration=%v", obs.lastState, obs.duration)
	case <-time.After(1 * time.Second):
		t.Fatal("observer was not called")
	}
}

// testMessageObserver is a simple implementation of qdef.MessageObserver for testing.
type testMessageObserver struct {
	onComplete func(src qdef.Identity, dest qdef.Addr, msgID qdef.MessageID, lastState qdef.MessageState, duration time.Duration, err error)
}

func (o *testMessageObserver) OnMessageComplete(src qdef.Identity, dest qdef.Addr, msgID qdef.MessageID, lastState qdef.MessageState, duration time.Duration, err error) {
	if o.onComplete != nil {
		o.onComplete(src, dest, msgID, lastState, duration, err)
	}
}

// TestStatusUpdates tests that status updates are sent to the client during routing.
func TestStatusUpdates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision both clients.
	providerID := qdef.Identity{Hostname: "provider-client"}
	providerCertPEM, providerKeyPEM, err := authManager.IssueClientCertificate(&providerID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(providerID, qdef.StatusAuthorized)
	assertNoError(t, err)

	requesterID := qdef.Identity{Hostname: "requester-client"}
	requesterCertPEM, requesterKeyPEM, err := authManager.IssueClientCertificate(&requesterID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(requesterID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// Setup server.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		Auth:              authManager,
		ResolutionTimeout: 5 * time.Second,
		JobTimeout:        5 * time.Second,
	})
	assertNoError(t, err)

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	// Setup provider client.
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

	Handle(providerClient, "test-echo", func(ctx context.Context, id qdef.Identity, req *string) (*string, error) {
		resp := "echo: " + *req
		return &resp, nil
	})

	err = providerClient.Connect(ctx)
	assertNoError(t, err)
	defer providerClient.Close()

	if !waitForState(t, providerObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("provider client did not connect in time")
	}

	providerClient.SetDevices([]qdef.DeviceInfo{
		{ID: "echo-device", Name: "Echo Device", ServiceType: "test-echo"},
	})
	err = providerClient.TriggerUpdateDevices(ctx)
	assertNoError(t, err)

	provisionedID, _ := providerStore.GetIdentity()
	providerFP := provisionedID.Fingerprint

	// Setup requester using raw QUIC to capture status updates.
	requesterStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: requesterID,
	}
	err = requesterStore.SaveCredentials(requesterCertPEM, requesterKeyPEM)
	assertNoError(t, err)

	tlsCert, err := requesterStore.GetClientCertificate()
	assertNoError(t, err)
	rootCAs, err := requesterStore.GetRootCAs()
	assertNoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		ServerName:   "localhost",
	}

	conn, err := quic.DialAddr(ctx, quicAddr, tlsConfig, nil)
	assertNoError(t, err)
	defer conn.CloseWithError(0, "test done")

	stream, err := conn.OpenStreamSync(ctx)
	assertNoError(t, err)
	defer stream.Close()

	enc := cbor.NewEncoder(stream)
	dec := cbor.NewDecoder(stream)

	// Send request.
	msg := qdef.Message{
		ID: 12345,
		Target: qdef.Addr{
			Service: qdef.ServiceUser,
			Machine: providerFP,
			Type:    "test-echo",
			Device:  "echo-device",
		},
		Payload: mustMarshal("hello"),
	}
	err = enc.Encode(msg)
	assertNoError(t, err)

	// Collect all messages (status updates + final response).
	var messages []qdef.Message
	for {
		var resp qdef.Message
		stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		err := dec.Decode(&resp)
		if err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		messages = append(messages, resp)

		// Stop when we get a non-status-update message.
		if resp.Action != qdef.MsgActionStatusUpdate {
			break
		}
	}

	// Should have received status updates.
	t.Logf("Received %d messages", len(messages))
	for i, m := range messages {
		t.Logf("  [%d] ID=%d, State=%v, Action=%v, Error=%q",
			i, m.ID, m.State, m.Action, m.Error)
	}

	// Should have at least one status update and one final response.
	if len(messages) < 2 {
		t.Errorf("expected at least 2 messages (status updates + response), got %d", len(messages))
	}

	// Last message should be the final response.
	final := messages[len(messages)-1]
	if final.Action == qdef.MsgActionStatusUpdate {
		t.Error("last message should not be a status update")
	}
	if final.Error != "" {
		t.Errorf("unexpected error in final response: %s", final.Error)
	}

	var response string
	err = cbor.Unmarshal(final.Payload, &response)
	assertNoError(t, err)
	assertEqual(t, "echo: hello", response)
}

func mustMarshal(v any) cbor.RawMessage {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// TestInvalidAction_AckToServer tests that a client sending MsgActionAck to the server
// has its stream closed (misbehaving client protection).
func TestInvalidAction_AckToServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision a client.
	clientID := qdef.Identity{Hostname: "test-client"}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&clientID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(clientID, qdef.StatusAuthorized)
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

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// Setup client using raw QUIC to send invalid action.
	clientStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: clientID,
	}
	err = clientStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	tlsCert, err := clientStore.GetClientCertificate()
	assertNoError(t, err)
	rootCAs, err := clientStore.GetRootCAs()
	assertNoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		ServerName:   "localhost",
	}

	conn, err := quic.DialAddr(ctx, quicAddr, tlsConfig, nil)
	assertNoError(t, err)
	defer conn.CloseWithError(0, "test done")

	stream, err := conn.OpenStreamSync(ctx)
	assertNoError(t, err)

	enc := cbor.NewEncoder(stream)
	dec := cbor.NewDecoder(stream)

	// Send a message with Action=Ack (invalid - only Deliver is allowed from client).
	invalidMsg := qdef.Message{
		ID:     1,
		Action: qdef.MsgActionAck, // Invalid action
		Target: qdef.Addr{
			Service: qdef.ServiceSystem,
			Type:    "devices",
		},
	}
	err = enc.Encode(invalidMsg)
	assertNoError(t, err)

	// Try to read a response - should fail because server closes the stream.
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp qdef.Message
	err = dec.Decode(&resp)

	// Should get EOF or error because server closed the stream.
	if err == nil {
		t.Errorf("expected error (stream closed), got response: %+v", resp)
	} else {
		t.Logf("Got expected error (server closed stream due to invalid action): %v", err)
	}
}

// TestInvalidAction_StatusUpdateToServer tests that a client sending MsgActionStatusUpdate
// to the server has its stream closed (misbehaving client protection).
func TestInvalidAction_StatusUpdateToServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision a client.
	clientID := qdef.Identity{Hostname: "test-client"}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&clientID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(clientID, qdef.StatusAuthorized)
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

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// Setup client using raw QUIC to send invalid action.
	clientStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: clientID,
	}
	err = clientStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	tlsCert, err := clientStore.GetClientCertificate()
	assertNoError(t, err)
	rootCAs, err := clientStore.GetRootCAs()
	assertNoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		ServerName:   "localhost",
	}

	conn, err := quic.DialAddr(ctx, quicAddr, tlsConfig, nil)
	assertNoError(t, err)
	defer conn.CloseWithError(0, "test done")

	stream, err := conn.OpenStreamSync(ctx)
	assertNoError(t, err)

	enc := cbor.NewEncoder(stream)
	dec := cbor.NewDecoder(stream)

	// Send a message with Action=StatusUpdate (invalid - only Deliver is allowed from client).
	invalidMsg := qdef.Message{
		ID:     1,
		Action: qdef.MsgActionStatusUpdate, // Invalid action
		State:  qdef.MsgStateResolvedMachine,
		Target: qdef.Addr{
			Service: qdef.ServiceSystem,
			Type:    "devices",
		},
	}
	err = enc.Encode(invalidMsg)
	assertNoError(t, err)

	// Try to read a response - should fail because server closes the stream.
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp qdef.Message
	err = dec.Decode(&resp)

	// Should get EOF or error because server closed the stream.
	if err == nil {
		t.Errorf("expected error (stream closed), got response: %+v", resp)
	} else {
		t.Logf("Got expected error (server closed stream due to invalid action): %v", err)
	}
}

// TestInvalidAction_ValidDeliverWorks tests that a valid Deliver action still works correctly
// after the validation code was added.
func TestInvalidAction_ValidDeliverWorks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Pre-provision a client.
	clientID := qdef.Identity{Hostname: "test-client"}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&clientID, "test-role")
	assertNoError(t, err)
	err = authManager.SetStatus(clientID, qdef.StatusAuthorized)
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

	server.SetRoleDef("test-role", qdef.RoleConfig{
		Provides: []string{"test-echo"},
		SendsTo:  []string{"test-echo"},
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// Setup client using raw QUIC.
	clientStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: clientID,
	}
	err = clientStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	tlsCert, err := clientStore.GetClientCertificate()
	assertNoError(t, err)
	rootCAs, err := clientStore.GetRootCAs()
	assertNoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		ServerName:   "localhost",
	}

	conn, err := quic.DialAddr(ctx, quicAddr, tlsConfig, nil)
	assertNoError(t, err)
	defer conn.CloseWithError(0, "test done")

	stream, err := conn.OpenStreamSync(ctx)
	assertNoError(t, err)
	defer stream.Close()

	enc := cbor.NewEncoder(stream)
	dec := cbor.NewDecoder(stream)

	// Send a valid device update request with Action=Deliver (explicit, but also default).
	deviceReq := qdef.DeviceUpdateRequest{
		Hostname: "test-client",
		Devices: []qdef.DeviceInfo{
			{ID: "test-device", Name: "Test Device", ServiceType: "test-echo"},
		},
	}
	validMsg := qdef.Message{
		ID:     1,
		Action: qdef.MsgActionDeliver, // Valid action (also the zero value)
		Target: qdef.Addr{
			Service: qdef.ServiceSystem,
			Type:    "devices",
		},
		Payload: mustMarshal(deviceReq),
	}
	err = enc.Encode(validMsg)
	assertNoError(t, err)

	// Should get a valid response.
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp qdef.Message
	err = dec.Decode(&resp)
	assertNoError(t, err)

	if resp.Error != "" {
		t.Errorf("unexpected error in response: %s", resp.Error)
	}
	t.Logf("Got valid response for Deliver action: ID=%d", resp.ID)
}
