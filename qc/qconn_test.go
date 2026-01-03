package qc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
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

func assertEqual(t *testing.T, expected, actual interface{}) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("values are not equal:\nexpected: %[1]v (%[1]T)\nactual:   %[2]v (%[2]T)", expected, actual)
	}
}

func assertNotEqual(t *testing.T, unexpected, actual interface{}) {
	t.Helper()
	if reflect.DeepEqual(unexpected, actual) {
		t.Fatalf("values should not be equal:\nunexpected: %[1]v (%[1]T)\nactual:     %[2]v (%[2]T)", unexpected, actual)
	}
}

func assertNotNil(t *testing.T, v interface{}) {
	t.Helper()
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Ptr && reflect.ValueOf(v).IsNil()) {
		t.Fatal("expected value to be not nil, but it was")
	}
}

// --- Test Setup ---

func setupTestInfra(ctx context.Context, t *testing.T) (*InMemoryAuthorizationManager, *TestStreamHandler, *TestStreamHandler, *TestObserver, *TestObserver) {
	authManager := NewInMemoryAuthorizationManager()
	clientHandler := NewTestStreamHandler(t)
	serverHandler := NewTestStreamHandler(t)
	clientObs := NewTestObserver(ctx, t)
	serverObs := NewTestObserver(ctx, t)

	return authManager, clientHandler, serverHandler, clientObs, serverObs
}

// --- Tests ---

func TestFullConnectionLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, clientHandler, serverHandler, clientObs, serverObs := setupTestInfra(ctx, t)
	defer clientHandler.Close()
	defer serverHandler.Close()

	// 1. Setup Server with dynamic ports.
	serverCert, err := authManager.IssueServerCertificate(Identity{Hostname: testServerHostname})
	assertNoError(t, err)

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)

	quicAddr := packetConn.LocalAddr().String()

	server := NewServer(ServerOpt{
		ListenOn:        "",
		ProvisionTokens: []string{testProvisionToken},
		ServerCert:      serverCert,
		CACert:          authManager.RootCert(),
		Auth:            authManager,
		Handler:         serverHandler,
		Observer:        serverObs,
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// 2. Client connects with NO initial credentials.
	// It should use the provision token to automatically provision itself.
	id := Identity{Hostname: testClientHostname}
	credStore := &InMemoryCredentialStore{rootCACert: authManager.RootCert(), identity: id, provisionToken: testProvisionToken}

	resolver := &MockResolver{}
	resolver.SetAddress(quicAddr)
	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Handler:         clientHandler,
		Observer:        clientObs,
	})
	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	select {
	case <-clientHandler.Connects:
		t.Log("Test: Client connected. Authorizing now...")
		err = authManager.SetStatus(id, StatusAuthorized)
		assertNoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("client did not connect/provision in time")
	}

	// 5. Open a stream and verify communication.
	conn := client.Connection()
	assertNotNil(t, conn)

	t.Log("Test: Client opening a new stream.")
	stream, err := conn.OpenStreamSync(ctx)
	assertNoError(t, err)
	defer stream.Close()

	// Send an empty message to force stream frame.
	clientHandler.DataToSend <- ""

	// --- THE FIX: Start a full, bidirectional handler for the client's stream ---
	// Start a goroutine to read from the stream and populate the client's receive channel.
	go func() {
		dec := cbor.NewDecoder(stream)
		t.Log("Client decoder started")
		for {
			t.Log("Client attempting to decode")
			var msg string
			if err := dec.Decode(&msg); err != nil {
				t.Logf("Client decode error: %v", err)
				return // Expected on stream close.
			}
			t.Logf("Client decoded msg: %s", msg)
			clientHandler.ReceivedData <- msg
		}
	}()

	// Start a goroutine to write to the stream from the client's send channel.
	go func() {
		enc := cbor.NewEncoder(stream)
		for msg := range clientHandler.DataToSend {
			if err := enc.Encode(msg); err != nil {
				t.Logf("client test writer error: %v", err)
				return
			}
		}
	}()
	// --- END FIX ---

	t.Log("Test: Server sending 'hello from server'.")
	serverHandler.DataToSend <- "hello from server"
	select {
	case msg := <-clientHandler.ReceivedData:
		assertEqual(t, "hello from server", msg)
		t.Log("Test: Client successfully received message from server.")

		msg = <-serverHandler.ReceivedData
		assertEqual(t, "", msg)
		t.Log("Test: Server received initial empty message.")
	case <-time.After(3 * time.Second):
		t.Fatal("client did not receive message")
	}

	t.Log("Test: Client sending 'hello from client'.")
	clientHandler.DataToSend <- "hello from client"
	select {
	case msg := <-serverHandler.ReceivedData:
		assertEqual(t, "hello from client", msg)
		t.Log("Test: Server successfully received message from client.")
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive message")
	}
}

func TestConnectionMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, clientHandler, _, clientObs, _ := setupTestInfra(ctx, t)
	defer clientHandler.Close()

	// 1. Setup common certs and TLS configs.
	serverCert, err := authManager.IssueServerCertificate(Identity{Hostname: testServerHostname})
	assertNoError(t, err)
	id := Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(authManager.RootCert())
	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	credStore := &InMemoryCredentialStore{rootCACert: authManager.RootCert(), identity: Identity{Hostname: testClientHostname}, provisionToken: testProvisionToken}
	err = credStore.SaveCredentials(Identity{Hostname: testClientHostname}, clientCertPEM, clientKeyPEM)
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
	resolver := &MockResolver{}
	resolver.SetAddress(addrA)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Handler:         clientHandler,
		Observer:        clientObs,
	})
	err = client.Connect(context.Background())
	assertNoError(t, err)
	defer client.Close()

	select {
	case <-clientHandler.Connects:
		t.Logf("Client connected to Server A at %s", addrA)
	case <-time.After(3 * time.Second):
		t.Fatal("client did not connect to server A")
	}

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
		clientHandler.Connects <- conn // Signal re-connection.
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
	select {
	case <-clientHandler.Connects:
		t.Log("Client successfully reconnected to Server B")
	case <-time.After(10 * time.Second): // Reconnect backoff can take a few seconds.
		t.Fatal("client did not reconnect to server B")
	}

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
	authManager, clientHandler, _, clientObs, _ := setupTestInfra(ctx, t)
	defer clientHandler.Close()

	serverCert, err := authManager.IssueServerCertificate(Identity{Hostname: testServerHostname})
	assertNoError(t, err)

	id := Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &InMemoryCredentialStore{rootCACert: authManager.RootCert(), provisionToken: testProvisionToken}
	err = credStore.SaveCredentials(Identity{Hostname: testClientHostname}, clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	resolver := &MockResolver{}
	resolver.SetAddress("127.0.0.1:12345") // Dummy initial address.

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Handler:         clientHandler,
		Observer:        clientObs,
		ResolverRefresh: 500 * time.Millisecond,
	})

	// 1. Initial connect attempt (will fail, but supervisor will start).
	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// 2. Setup actual server.
	caPool := x509.NewCertPool()
	caPool.AddCert(authManager.RootCert())
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
	select {
	case <-clientHandler.Connects:
		t.Log("Client connected after supervisor DNS update")
	case <-time.After(10 * time.Second):
		t.Fatal("client did not connect after DNS update")
	}
}

func TestServerDowntimeRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, clientHandler, serverHandler, clientObs, serverObs := setupTestInfra(ctx, t)
	defer clientHandler.Close()
	defer serverHandler.Close()

	serverCert, err := authManager.IssueServerCertificate(Identity{Hostname: testServerHostname})
	assertNoError(t, err)
	id := Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &InMemoryCredentialStore{rootCACert: authManager.RootCert(), provisionToken: testProvisionToken}
	err = credStore.SaveCredentials(Identity{Hostname: testClientHostname}, clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	addr := packetConn.LocalAddr().String()

	resolver := &MockResolver{}
	resolver.SetAddress(addr)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Handler:         clientHandler,
		Observer:        clientObs,
		KeepAlivePeriod: 500 * time.Millisecond,
	})

	// 1. Start Server.
	server := NewServer(ServerOpt{
		ServerCert:      serverCert,
		CACert:          authManager.RootCert(),
		Auth:            authManager,
		Handler:         serverHandler,
		Observer:        serverObs,
		KeepAlivePeriod: 500 * time.Millisecond,
	})
	authManager.SetStatus(id, StatusAuthorized)

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	// 2. Connect Client.
	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	select {
	case <-clientHandler.Connects:
		t.Log("Initial connection established")
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for initial connection")
	}

	// 3. STOP Server. (Close the packetConn)
	t.Log("Stopping server...")
	packetConn.Close()

	// Wait for client to detect loss.
	time.Sleep(500 * time.Millisecond)

	// 4. RESTART Server on same port.
	t.Log("Restarting server on same port...")
	packetConn2, err := net.ListenPacket("udp", addr)
	assertNoError(t, err)
	defer packetConn2.Close()

	err = server.Serve(ctx, packetConn2)
	assertNoError(t, err)

	// 5. Wait for Client to RECONNECT.
	select {
	case <-clientHandler.Connects:
		t.Log("Client reconnected after server downtime")
	case <-time.After(10 * time.Second):
		t.Fatal("client failed to reconnect after server downtime")
	}
}

func TestContinuousRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	authManager, clientHandler, _, clientObs, _ := setupTestInfra(ctx, t)
	defer clientHandler.Close()

	id := Identity{Hostname: testClientHostname}

	clientCertPEM, clientKeyPEM, err := authManager.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &InMemoryCredentialStore{rootCACert: authManager.RootCert(), provisionToken: testProvisionToken}
	err = credStore.SaveCredentials(id, clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	// Point to a dead address initially.
	resolver := &MockResolver{}
	resolver.SetAddress("127.0.0.1:54321")

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Handler:         clientHandler,
		Observer:        clientObs,
	})

	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// Wait for a few failed attempts (should be visible in logs if we could see them).
	time.Sleep(2 * time.Second)

	// Now bring up a server on a NEW address and update resolver.
	serverCert, err := authManager.IssueServerCertificate(Identity{Hostname: testServerHostname})
	assertNoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AddCert(authManager.RootCert())
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
	select {
	case <-clientHandler.Connects:
		t.Log("Client connected due to continuous retry logic")
	case <-time.After(10 * time.Second):
		t.Fatal("client did not connect after server came online")
	}
}

func TestProvisioningRetry(t *testing.T) {
	// 1. Setup Mock Resolver.
	mockRes := &MockResolver{}
	addr := "127.0.0.1:54322"
	mockRes.SetAddress(addr)

	// 2. Setup authManager (which is also the CA).
	auth := NewInMemoryAuthorizationManager()

	// 3. Setup client with a ProvisionToken but NO credentials.
	store := &InMemoryCredentialStore{
		rootCACert:     auth.RootCert(),
		provisionToken: testProvisionToken,
	}
	client := NewClient(ClientOpt{
		ServerHostname:  "test-server",
		CredentialStore: store,
		Resolver:        mockRes,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 4. Client should be in provisioning loop, failing to dial the non-existent server.
	time.Sleep(500 * time.Millisecond)

	// 5. Start the provisioning server now.
	// 5. Start the provisioning server now.
	serverCert, err := auth.IssueServerCertificate(Identity{Hostname: "test-server"})
	if err != nil {
		t.Fatalf("failed to issue server cert: %v", err)
	}

	server := NewServer(ServerOpt{
		ServerCert:      serverCert,
		CACert:          auth.RootCert(),
		Auth:            auth,
		ProvisionTokens: []string{testProvisionToken},
		Observer:        NewTestObserver(ctx, t),
	})

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
	authManager, clientHandler, _, obs, serverObs := setupTestInfra(ctx, t)
	defer clientHandler.Close()

	id := Identity{Hostname: testServerHostname}

	serverCert, err := authManager.IssueServerCertificate(id)
	assertNoError(t, err)

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	defer packetConn.Close()
	quicAddr := packetConn.LocalAddr().String()

	server := NewServer(ServerOpt{
		ProvisionTokens: []string{testProvisionToken},
		ServerCert:      serverCert,
		CACert:          authManager.RootCert(),
		Auth:            authManager,
		Observer:        serverObs,
	})

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)

	credStore := &InMemoryCredentialStore{rootCACert: authManager.RootCert(), identity: Identity{Hostname: testClientHostname}, provisionToken: testProvisionToken}
	resolver := &MockResolver{}
	resolver.SetAddress(quicAddr)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Handler:         clientHandler,
		Observer:        obs,
	})

	err = client.Connect(ctx)
	assertNoError(t, err)
	defer client.Close()

	// Verify states
	expectedStates := []ClientState{StateProvisioning, StateProvisioned, StateConnecting, StateConnected}
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
	auth := NewInMemoryAuthorizationManager()
	serverCert, err := auth.IssueServerCertificate(Identity{Hostname: testServerHostname})
	assertNoError(t, err)

	id := Identity{Hostname: testClientHostname}
	clientCertPEM, clientKeyPEM, err := auth.IssueClientCertificate(&id)
	assertNoError(t, err)

	credStore := &InMemoryCredentialStore{rootCACert: auth.RootCert()}
	err = credStore.SaveCredentials(Identity{Hostname: testClientHostname}, clientCertPEM, clientKeyPEM)
	assertNoError(t, err)

	// Short timeout for fast testing.

	setup := func(t *testing.T) (context.Context, context.CancelFunc, *Client, *InterceptingPacketConn, *TestObserver) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		sObs := NewTestObserver(ctx, t)
		server := NewServer(ServerOpt{
			ServerCert:      serverCert,
			CACert:          auth.RootCert(),
			Auth:            auth,
			KeepAlivePeriod: 500 * time.Millisecond,
			Observer:        sObs,
		})
		auth.SetStatus(id, StatusAuthorized)

		sConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		assertNoError(t, err)
		serverIConn := NewInterceptingPacketConn(sConn)
		err = server.Serve(ctx, serverIConn)
		assertNoError(t, err)

		resolver := &MockResolver{}
		resolver.SetAddress(sConn.LocalAddr().String())

		obs := NewTestObserver(ctx, t)
		client := NewClient(ClientOpt{
			ServerHostname:  testServerHostname,
			CredentialStore: credStore,
			Resolver:        resolver,
			Observer:        obs,
			KeepAlivePeriod: 500 * time.Millisecond,
		})

		return ctx, cancel, client, serverIConn, obs
	}

	const timeout = 5 * time.Second

	waitForState := func(t *testing.T, obs *TestObserver, expected ClientState, timeout time.Duration) {
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

		waitForState(t, obs, StateConnected, timeout)

		// Now block EVERYTHING on the server side.
		sIConn.BlockReads(true)
		sIConn.BlockWrites(true)

		// Client should sense the timeout and move to disconnected (then connecting).
		waitForState(t, obs, StateDisconnected, timeout)
	})

	t.Run("Unidirectional_StoC_Block", func(t *testing.T) {
		ctx, cancel, client, sIConn, obs := setup(t)
		defer cancel()

		err := client.Connect(ctx)
		assertNoError(t, err)

		waitForState(t, obs, StateConnected, timeout)

		sIConn.BlockWrites(true)

		// Client should timeout because it's not receiving anything from the server.
		waitForState(t, obs, StateDisconnected, timeout)
	})

	t.Run("Unidirectional_CtoS_Block", func(t *testing.T) {
		ctx, cancel, client, sIConn, obs := setup(t)
		defer cancel()

		err := client.Connect(ctx)
		assertNoError(t, err)

		waitForState(t, obs, StateConnected, timeout)

		sIConn.BlockReads(true)

		// Server won't receive heartbeats/ACKs from client.
		// Client might also sense failure if it doesn't get ACKs for its heartbeats.
		// In QUIC, heartbeats expect ACKs. If the client doesn't get ACKs, it will timeout.
		waitForState(t, obs, StateDisconnected, timeout)
	})
}
