package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
	"github.com/quic-go/quic-go"
)

// ... (Test Helpers and Setup functions remain unchanged) ...
const (
	testServerHostname = "localhost"
	testClientHostname = "test-client-01"
	testProvisionToken = "supersecret"
)

// --- Test Helpers ---

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertEqual(t *testing.T, expected, actual any) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("values are not equal:\nexpected: %[1]v (%[1]T)\nactual:   %[2]v (%[2]T)", expected, actual)
	}
}

func assertNotEqual(t *testing.T, unexpected, actual any) {
	t.Helper()
	if reflect.DeepEqual(unexpected, actual) {
		t.Fatalf("values should not be equal:\nunexpected: %[1]v (%[1]T)\nactual:     %[2]v (%[2]T)", unexpected, actual)
	}
}

func assertNotNil(t *testing.T, v any) {
	t.Helper()
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Ptr && reflect.ValueOf(v).IsNil()) {
		t.Fatal("expected value to be not nil, but it was")
	}
}

// --- Test Setup ---

func setupTestInfra(ctx context.Context, t *testing.T) (*qmock.InMemoryAuthorizationManager, *qmock.TestStreamHandler, *qmock.TestObserver, *qmock.TestObserver) {
	authManager := qmock.NewInMemoryAuthorizationManager()
	serverHandler := qmock.NewTestStreamHandler(t)
	serverHandler.Auth = authManager

	clientObs := qmock.NewTestObserver(ctx, t)
	serverObs := qmock.NewTestObserver(ctx, t)

	return authManager, serverHandler, clientObs, serverObs
}

// waitForState waits for a specific state from the observer.
func waitForState(t *testing.T, obs *qmock.TestObserver, expected qdef.ClientState, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case state := <-obs.States:
			if state == expected {
				return true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	return false
}

// --- Tests ---

func TestFullConnectionLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, serverHandler, clientObs, serverObs := setupTestInfra(ctx, t)
	defer serverHandler.Close()

	// 1. Setup Server with dynamic ports.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)

	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		ListenOn:        "",
		ProvisionTokens: []string{testProvisionToken},
		Auth:            authManager,
		Observer:        serverObs,
	})
	assertNoError(t, err)
	serverHandler.RegisterHandlers(&server.Router)

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// 2. Client connects with NO initial credentials.
	// It should use the provision token to automatically provision itself.
	id := qdef.Identity{Hostname: testClientHostname}
	credStore := &qmock.InMemoryCredentialStore{RootCA: authManager.RootCert(), Identity: id, Token: testProvisionToken}

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)
	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        clientObs,
	})
	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// Wait for client to connect
	if !waitForState(t, clientObs, qdef.StateConnected, 5*time.Second) {
		t.Fatal("client did not connect/provision in time")
	}
	t.Log("Test: Client connected. Authorizing now...")
	provisionedID, _ := credStore.GetIdentity()
	err = authManager.SetStatus(provisionedID, qdef.StatusAuthorized)
	assertNoError(t, err)

	// 5. Verify bidirectional communication using the high-level Request API.
	t.Log("Test: Verifying bidirectional communication via Request.")

	// Prepare data for the server to send back when it handles our request.
	serverHandler.DataToSend <- "hello from server"

	resp := ""
	target := qdef.Addr{Service: qdef.ServiceUser} // Empty Type matches the test handler.
	_, err = client.Request(ctx, target, "hello from client", &resp)
	assertNoError(t, err)

	assertEqual(t, "hello from server", resp)
	t.Log("Test: Client successfully received 'hello from server' as response.")

	select {
	case msg := <-serverHandler.ReceivedData:
		assertEqual(t, "hello from client", msg)
		t.Log("Test: Server received 'hello from client'.")
	default:
		t.Fatal("server did not receive message")
	}
}

func TestConnectionMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, _, clientObs, _ := setupTestInfra(ctx, t)

	// 1. Setup common certs and TLS configs.
	id := qdef.Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(authManager.RootCert())
	serverCert, err := authManager.ServerCertificate()
	assertNoError(t, err)
	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	credStore := &qmock.InMemoryCredentialStore{RootCA: authManager.RootCert(), Identity: qdef.Identity{Hostname: testClientHostname}, Token: testProvisionToken}
	err = credStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	// 2. Start a minimal Server A.
	listenerA, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, nil)
	assertNoError(t, err)
	addrA := listenerA.Addr().String()
	go func() {
		conn, err := listenerA.Accept(context.Background())
		if err != nil {
			return // Expected on close.
		}
		<-conn.Context().Done()
	}()

	// 3. Connect client to Server A.
	resolver := &qmock.MockResolver{}
	resolver.SetAddress(addrA)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        clientObs,
	})
	err = client.Connect(context.Background())
	assertNoError(t, err)
	defer client.Close()

	if !waitForState(t, clientObs, qdef.StateConnected, 3*time.Second) {
		t.Fatal("client did not connect to server A")
	}
	t.Logf("Client connected to Server A at %s", addrA)

	// 4. Start a minimal Server B.
	listenerB, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, nil)
	assertNoError(t, err)
	defer listenerB.Close()
	addrB := listenerB.Addr().String()
	go func() {
		conn, err := listenerB.Accept(context.Background())
		if err != nil {
			return
		}
		<-conn.Context().Done()
	}()

	// 5. Update resolver to point to Server B.
	resolver.SetAddress(addrB)
	t.Logf("Updated resolver to point to Server B at %s", addrB)

	// 6. Kill Server A to trigger the client's reconnect logic.
	t.Logf("Closing Server A at %s", addrA)
	listenerA.Close()
	// Also close the actual connection to ensure immediate detection.
	client.mu.Lock()
	if client.conn != nil {
		_ = client.conn.CloseWithError(0, "test: server A killed")
	}
	client.mu.Unlock()

	// 7. Wait for the client's monitorConnection to reconnect to Server B.
	// First wait for disconnect, then reconnect.
	if !waitForState(t, clientObs, qdef.StateDisconnected, 5*time.Second) {
		t.Log("Warning: did not see disconnect state")
	}
	if !waitForState(t, clientObs, qdef.StateConnected, 10*time.Second) {
		t.Fatal("client did not reconnect to server B")
	}
	t.Log("Client successfully reconnected to Server B")

	// 8. Verify the new connection details.
	conn := client.Connection()
	assertNotNil(t, conn)
	assertNotEqual(t, addrA, conn.RemoteAddr().String())
	assertEqual(t, testServerHostname, conn.ConnectionState().TLS.ServerName)
	assertEqual(t, addrB, conn.RemoteAddr().String())
	t.Logf("Successfully migrated from %s to %s", addrA, conn.RemoteAddr().String())
}

func TestSupervisorDNSUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, _, clientObs, _ := setupTestInfra(ctx, t)

	id := qdef.Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &qmock.InMemoryCredentialStore{RootCA: authManager.RootCert(), Identity: qdef.Identity{Hostname: testClientHostname}, Token: testProvisionToken}
	err = credStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	resolver := &qmock.MockResolver{}
	resolver.SetAddress("127.0.0.1:12345") // Dummy initial address.

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        clientObs,
		ResolverRefresh: 50 * time.Millisecond,
		DialTimeout:     100 * time.Millisecond,
	})

	// 1. Initial connect attempt (will fail, but supervisor will start).
	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// 2. Setup actual server.
	caPool := x509.NewCertPool()
	caPool.AddCert(authManager.RootCert())

	serverCert, err := authManager.ServerCertificate()
	assertNoError(t, err)

	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, nil)
	assertNoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	// 3. Update resolver with real address. Supervisor should pick it up.
	// We wait slightly longer than ResolverRefresh to ensure the ticker fires.
	resolver.SetAddress(addr)
	t.Logf("Updated resolver to point to real address: %s", addr)

	// Since supervisor doesn't automatically call attemptConnect on address change yet
	// (it just updates lastAddr), we have to wait for something else to trigger it
	// OR wait for the initial connection attempt to fail and then monitorConnection to retry.
	// Actually, supervisor SHOULD probably trigger a reconnect if addr changes.

	// For now, monitorConnection will retry every i seconds.
	if !waitForState(t, clientObs, qdef.StateConnected, 10*time.Second) {
		t.Fatal("client did not connect after DNS update")
	}
	t.Log("Client connected after supervisor DNS update")
}

func TestServerDowntimeRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, serverHandler, clientObs, serverObs := setupTestInfra(ctx, t)
	defer serverHandler.Close()
	id := qdef.Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &qmock.InMemoryCredentialStore{RootCA: authManager.RootCert(), Identity: qdef.Identity{Hostname: testClientHostname}, Token: testProvisionToken}
	err = credStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	addr := packetConn.LocalAddr().String()

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(addr)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        clientObs,
		KeepAlivePeriod: 500 * time.Millisecond,
	})

	// 1. Start Server.
	server, err := NewServer(ServerOpt{
		Auth:            authManager,
		Observer:        serverObs,
		KeepAlivePeriod: 500 * time.Millisecond,
	})
	assertNoError(t, err)
	authManager.SetStatus(id, qdef.StatusAuthorized)

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// 2. Connect Client.
	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	if !waitForState(t, clientObs, qdef.StateConnected, 3*time.Second) {
		t.Fatal("timed out waiting for initial connection")
	}
	t.Log("Initial connection established")

	// 3. STOP Server. (Close the packetConn)
	t.Log("Stopping server...")
	packetConn.Close()

	// Wait for client to detect loss.
	time.Sleep(100 * time.Millisecond)

	// 4. RESTART Server on same port.
	t.Log("Restarting server on same port...")
	packetConn2, err := net.ListenPacket("udp", addr)
	assertNoError(t, err)
	defer packetConn2.Close()

	err = server.Serve(ctx, packetConn2)
	assertNoError(t, err)

	// 5. Wait for Client to RECONNECT.
	if !waitForState(t, clientObs, qdef.StateConnected, 10*time.Second) {
		t.Fatal("client failed to reconnect after server downtime")
	}
	t.Log("Client reconnected after server downtime")
}

func TestContinuousRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, _, clientObs, _ := setupTestInfra(ctx, t)

	id := qdef.Identity{Hostname: testClientHostname}

	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &qmock.InMemoryCredentialStore{RootCA: authManager.RootCert(), Identity: id, Token: testProvisionToken}
	err = credStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	// Point to a dead address initially.
	resolver := &qmock.MockResolver{}
	resolver.SetAddress("127.0.0.1:54321")

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        clientObs,
		DialTimeout:     100 * time.Millisecond,
	})

	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// Wait for a few failed attempts (should be visible in logs if we could see them).
	time.Sleep(250 * time.Millisecond)

	// Now bring up a server on a NEW address and update resolver.
	caPool := x509.NewCertPool()
	caPool.AddCert(authManager.RootCert())
	serverCert, err := authManager.ServerCertificate()
	assertNoError(t, err)
	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, nil)
	assertNoError(t, err)
	defer listener.Close()

	resolver.SetAddress(listener.Addr().String())
	t.Logf("Updated resolver to point to real address: %s", listener.Addr().String())

	// Client should eventually connect due to the supervisor's continuous retry.
	if !waitForState(t, clientObs, qdef.StateConnected, 10*time.Second) {
		t.Fatal("client did not connect after server came online")
	}
	t.Log("Client connected due to continuous retry logic")
}

func TestProvisioningRetry(t *testing.T) {
	// 1. Setup Mock Resolver.
	mockRes := &qmock.MockResolver{}
	addr := "127.0.0.1:54322"
	mockRes.SetAddress(addr)

	// 2. Setup authManager (which is also the CA).
	auth := qmock.NewInMemoryAuthorizationManager()

	// 3. Setup client with a ProvisionToken but NO credentials.
	store := &qmock.InMemoryCredentialStore{
		RootCA: auth.RootCert(),
		Token:  testProvisionToken,
	}
	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: store,
		Resolver:        mockRes,
		DialTimeout:     100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 4. Client should be in provisioning loop, failing to dial the non-existent server.
	time.Sleep(200 * time.Millisecond)

	// 5. Start the provisioning server now.

	serverHandler := qmock.NewTestStreamHandler(t)
	serverHandler.Auth = auth
	server, err := NewServer(ServerOpt{
		Auth:            auth,
		ProvisionTokens: []string{testProvisionToken},
		Observer:        qmock.NewTestObserver(ctx, t),
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	packetConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	defer packetConn.Close()

	if err := server.Serve(ctx, packetConn); err != nil {
		t.Fatalf("failed to serve: %v", err)
	}

	// 6. Wait for the client to provision and connect.
	var conn *quic.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn = client.Connection()
		if conn != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if conn == nil {
		t.Fatalf("Client failed to provision and connect after server came online")
	}

	// 7. Verify credentials were saved.
	cert, err := store.GetClientCertificate()
	if err != nil || len(cert.Certificate) == 0 {
		t.Errorf("Credentials should be saved in store")
	}
}

func TestClientObserver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, _, obs, serverObs := setupTestInfra(ctx, t)

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	serverHandler := qmock.NewTestStreamHandler(t)
	serverHandler.Auth = authManager
	server, err := NewServer(ServerOpt{
		ProvisionTokens: []string{testProvisionToken},
		Auth:            authManager,
		Observer:        serverObs,
	})
	assertNoError(t, err)

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	credStore := &qmock.InMemoryCredentialStore{RootCA: authManager.RootCert(), Identity: qdef.Identity{Hostname: testClientHostname}, Token: testProvisionToken}
	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        obs,
	})

	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// Verify states
	expectedStates := []qdef.ClientState{qdef.StateProvisioning, qdef.StateProvisioned, qdef.StateConnecting, qdef.StateConnected}
	for _, expected := range expectedStates {
		select {
		case state := <-obs.States:
			if state != expected {
				t.Errorf("expected state %s, got %s", expected, state)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for state %s", expected)
		}
	}

	// Verify logs (at least some)
	select {
	case log := <-obs.Logs:
		if log == "" {
			t.Error("received empty log")
		}
	case <-time.After(1 * time.Second):
		t.Error("timed out waiting for logs")
	}
}

func TestConnectionReliability(t *testing.T) {
	auth := qmock.NewInMemoryAuthorizationManager()
	id := qdef.Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := auth.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &qmock.InMemoryCredentialStore{Identity: id, Token: "test-token", RootCA: auth.RootCert()}
	err = credStore.SaveCredentials(clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	// Short timeout for fast testing.

	setup := func(t *testing.T) (context.Context, context.CancelFunc, *Client, *qmock.InterceptingPacketConn, *qmock.TestObserver) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		sObs := qmock.NewTestObserver(ctx, t)
		serverHandler := qmock.NewTestStreamHandler(t)
		serverHandler.Auth = auth
		server, err := NewServer(ServerOpt{
			Auth:            auth,
			KeepAlivePeriod: 100 * time.Millisecond,
			Observer:        sObs,
		})
		assertNoError(t, err)
		auth.SetStatus(id, qdef.StatusAuthorized)

		sConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		assertNoError(t, err)
		serverIConn := qmock.NewInterceptingPacketConn(sConn)
		err = server.Serve(ctx, serverIConn)
		assertNoError(t, err)

		resolver := &qmock.MockResolver{}
		resolver.SetAddress(sConn.LocalAddr().String())

		obs := qmock.NewTestObserver(ctx, t)
		client := NewClient(ClientOpt{
			ServerHostname:  testServerHostname,
			CredentialStore: credStore,
			Resolver:        resolver,
			Observer:        obs,
			KeepAlivePeriod: 100 * time.Millisecond,
			DialTimeout:     200 * time.Millisecond,
		})

		return ctx, cancel, client, serverIConn, obs
	}

	const timeout = 1 * time.Second

	waitForState := func(t *testing.T, obs *qmock.TestObserver, expected qdef.ClientState, timeout time.Duration) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			select {
			case state := <-obs.States:
				if state == expected {
					return
				}
			case <-time.After(100 * time.Millisecond):
			}
		}
		t.Fatalf("timed out waiting for state %s", expected)
	}

	t.Run("BidirectionalBlock", func(t *testing.T) {
		ctx, cancel, client, sIConn, obs := setup(t)
		defer cancel()

		err := client.Connect(ctx)
		assertNoError(t, err)

		waitForState(t, obs, qdef.StateConnected, timeout)

		// Now block EVERYTHING on the server side.
		sIConn.BlockReads(true)
		sIConn.BlockWrites(true)

		// Client should sense the timeout and move to disconnected (then connecting).
		waitForState(t, obs, qdef.StateDisconnected, timeout)
	})

	t.Run("Unidirectional_StoC_Block", func(t *testing.T) {
		ctx, cancel, client, sIConn, obs := setup(t)
		defer cancel()

		err := client.Connect(ctx)
		assertNoError(t, err)

		waitForState(t, obs, qdef.StateConnected, timeout)

		sIConn.BlockWrites(true)

		// Client should timeout because it's not receiving anything from the server.
		waitForState(t, obs, qdef.StateDisconnected, timeout)
	})

	t.Run("Unidirectional_CtoS_Block", func(t *testing.T) {
		ctx, cancel, client, sIConn, obs := setup(t)
		defer cancel()

		err := client.Connect(ctx)
		assertNoError(t, err)

		waitForState(t, obs, qdef.StateConnected, timeout)

		sIConn.BlockReads(true)

		// Server won't receive heartbeats/ACKs from client.
		// Client might also sense failure if it doesn't get ACKs for its heartbeats.
		// In QUIC, heartbeats expect ACKs. If the client doesn't get ACKs, it will timeout.
		waitForState(t, obs, qdef.StateDisconnected, timeout)
	})
}
