package qconn

import (
	"context"
	"crypto/rand"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
)

// TestRaceConditions is a stress test designed to expose race conditions.
// Run with: go test -race -count 10 ./qconn -run TestRaceConditions -v
func TestRaceConditions(t *testing.T) {
	const (
		numClients           = 3   // Number of concurrent clients
		goroutinesPerClient  = 5   // Goroutines per client sending requests
		requestsPerGoroutine = 100 // Max requests per goroutine
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup auth manager with fast cleanup and auto-authorization
	authManager := qmock.NewInMemoryAuthorizationManager()
	authManager.AuthorizeAll() // Auto-authorize all clients

	// Create handler that sleeps for random 3-13ms to simulate work
	handler := &raceTestHandler{t: t}

	// Setup server with aggressive intervals
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)

	quicAddr := packetConn.LocalAddr().String()
	serverObs := qmock.NewTestObserver(ctx, t)

	server, err := NewServer(ServerOpt{
		ListenOn:             "",
		ProvisionTokens:      []string{"race-test-token"},
		Auth:                 authManager,
		Observer:             serverObs,
		RenewalInterval:      10 * time.Millisecond, // Very fast renewal
		ProvisioningInterval: 10 * time.Millisecond, // Very fast provisioning
		KeepAlivePeriod:      50 * time.Millisecond, // Fast keepalive
		MaxIncomingStreams:   1000,
	})
	assertNoError(t, err)

	// Register handler
	handler.RegisterHandlers(&server.Router)

	err = server.Serve(ctx, packetConn)
	assertNoError(t, err)
	defer server.Close()

	t.Logf("Server listening on %s", quicAddr)

	// Create multiple clients with aggressive settings
	var clients []*Client
	var resolvers []*qmock.MockResolver
	var credStores []*qmock.InMemoryCredentialStore

	for i := range numClients {
		hostname := "race-client-" + string(rune('a'+i))

		// Pre-provision to avoid rate limiting during stress test
		id := qdef.Identity{Hostname: hostname}
		certPEM, keyPEM, err := authManager.IssueClientCertificate(&id, "race-test")
		assertNoError(t, err)

		credStore := &qmock.InMemoryCredentialStore{
			RootCA:   authManager.RootCert(),
			Identity: id,
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
		}
		credStores = append(credStores, credStore)

		resolver := &qmock.MockResolver{}
		resolver.SetAddress(quicAddr)
		resolvers = append(resolvers, resolver)

		clientObs := qmock.NewTestObserver(ctx, t)
		client := NewClient(ClientOpt{
			ServerHostname:  testServerHostname,
			CredentialStore: credStore,
			Resolver:        resolver,
			Observer:        clientObs,
			KeepAlivePeriod: 50 * time.Millisecond, // Fast keepalive
			ResolverRefresh: 20 * time.Millisecond, // Very fast resolver refresh
			DialTimeout:     500 * time.Millisecond,
		})
		clients = append(clients, client)
	}

	// Start all clients
	for _, client := range clients {
		err := client.Connect(ctx)
		assertNoError(t, err)
	}

	// Wait for clients to connect and authorize
	time.Sleep(30 * time.Millisecond)

	// Verify at least some clients connected
	connectedCount := 0
	for _, client := range clients {
		state := client.state.Current()
		if state == qdef.StateConnected || state == qdef.StateAuthorized {
			connectedCount++
		}
	}
	if connectedCount == 0 {
		t.Fatal("No clients connected")
	}
	t.Logf("Connected clients: %d/%d", connectedCount, numClients)

	// Create stop signal
	stopTest := make(chan struct{})

	// Track statistics
	var totalRequests atomic.Int64
	var successfulRequests atomic.Int64
	var failedRequests atomic.Int64

	// Track first few error messages for debugging
	var errMu sync.Mutex
	var firstErrors []string
	recordError := func(err error) {
		errMu.Lock()
		if len(firstErrors) < 5 {
			firstErrors = append(firstErrors, err.Error())
		}
		errMu.Unlock()
	}

	var wg sync.WaitGroup
	var wgBG sync.WaitGroup

	// Start request goroutines for each client
	for clientIdx, client := range clients {
		for g := 0; g < goroutinesPerClient; g++ {
			wg.Add(1)
			go func(cIdx, gIdx int, c *Client) {
				defer wg.Done()
				reqCount := 0
				for reqCount < requestsPerGoroutine {
					select {
					case <-stopTest:
						return
					case <-ctx.Done():
						return
					default:
					}

					totalRequests.Add(1)
					reqCount++

					// Send a test request
					target := qdef.Addr{
						Service: qdef.ServiceSystem,
						Type:    "race-test",
					}

					payload := raceTestRequest{
						ClientIdx:    cIdx,
						GoroutineIdx: gIdx,
						RequestNum:   reqCount,
						Timestamp:    time.Now().UnixNano(),
					}

					var resp raceTestResponse
					reqCtx, reqCancel := context.WithTimeout(ctx, 500*time.Millisecond)
					_, err := c.Request(reqCtx, target, &payload, &resp)
					reqCancel()

					if err != nil {
						failedRequests.Add(1)
						recordError(err)
					} else {
						successfulRequests.Add(1)
					}

					// Small random delay between requests
					sleepMs := randomInt(1, 5)
					time.Sleep(time.Duration(sleepMs) * time.Millisecond)
				}
			}(clientIdx, g, client)
		}
	}

	// Start resolver update goroutine (updates resolver addresses rapidly).
	wgBG.Add(1)
	go func() {
		defer wgBG.Done()
		ticker := time.NewTicker(15 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopTest:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Randomly update resolvers to trigger reconnection logic
				for _, resolver := range resolvers {
					resolver.SetAddress(quicAddr) // Same address but triggers update path
				}
			}
		}
	}()

	// Start device update goroutine (simulates device changes)
	wgBG.Add(1)
	go func() {
		defer wgBG.Done()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		count := 0
		for {
			select {
			case <-stopTest:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				count++
				for _, client := range clients {
					devices := []qdef.DeviceInfo{
						{ID: "dev1", Name: "Device 1", ServiceType: "race-test"},
						{ID: "dev2", Name: "Device 2 v" + string(rune('0'+count%10)), ServiceType: "race-test"},
					}
					client.SetDevices(devices)
				}
			}
		}
	}()

	// Start state query goroutine (reads client state rapidly)
	wgBG.Add(1)
	go func() {
		defer wgBG.Done()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopTest:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				for i, client := range clients {
					_ = client.state.Current()
					_, _ = credStores[i].GetIdentity()
				}
			}
		}
	}()

	// Start admin operations goroutine (list clients, etc.)
	wgBG.Add(1)
	go func() {
		defer wgBG.Done()
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopTest:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Query server for client list (exercises server-side locking)
				_ = authManager.ListClientsInfo(true, nil)
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wgBG.Wait()
		close(done)
	}()

	// Wait for clients to finish.
	wg.Wait()

	// Signal stop and wait for goroutines
	close(stopTest)

	select {
	case <-done:
		// All goroutines finished
	case <-time.After(3 * time.Second):
		t.Error("Warning: some goroutines did not finish in time")
	}

	// Force-close QUIC connections first to abort pending requests.
	// This is necessary because the supervisor may be blocked in Request calls
	// that don't respect context cancellation until the stream is closed.
	for _, client := range clients {
		if conn := client.Connection(); conn != nil {
			_ = conn.CloseWithError(0, "test cleanup")
		}
	}

	// Now stop clients (this will wait for supervisor to exit).
	for _, client := range clients {
		client.Close()
	}

	// Report statistics
	total := totalRequests.Load()
	successful := successfulRequests.Load()
	failed := failedRequests.Load()
	handlerCalls := handler.callCount.Load()

	t.Logf("Statistics:")
	t.Logf("  Total requests sent: %d", total)
	t.Logf("  Successful: %d", successful)
	t.Logf("  Failed: %d", failed)
	t.Logf("  Handler calls: %d", handlerCalls)

	// Print first few errors for debugging
	errMu.Lock()
	if len(firstErrors) > 0 {
		t.Logf("First errors (up to 5):")
		for i, errMsg := range firstErrors {
			t.Logf("  %d: %s", i+1, errMsg)
		}
	}
	errMu.Unlock()

	if total == 0 {
		t.Error("No requests were sent")
	}

	// We expect some failures due to timeouts, disconnections, etc.
	// But we should have some successes too.
	if successful == 0 && total > 10 {
		t.Error("No successful requests")
	}
}

// raceTestRequest is the request payload for the race test
type raceTestRequest struct {
	ClientIdx    int   `cbor:"client_idx"`
	GoroutineIdx int   `cbor:"goroutine_idx"`
	RequestNum   int   `cbor:"request_num"`
	Timestamp    int64 `cbor:"timestamp"`
}

// raceTestResponse is the response payload for the race test
type raceTestResponse struct {
	Processed bool  `cbor:"processed"`
	ServerTS  int64 `cbor:"server_ts"`
}

// raceTestHandler handles requests with random delays
type raceTestHandler struct {
	t         *testing.T
	callCount atomic.Int64
	mu        sync.Mutex
	closed    bool
}

func (h *raceTestHandler) RegisterHandlers(r *qdef.StreamRouter) {
	qdef.Handle(r, qdef.ServiceSystem, "race-test", h.handleRaceTest)
}

func (h *raceTestHandler) handleRaceTest(ctx context.Context, id qdef.Identity, req *raceTestRequest) (*raceTestResponse, error) {
	h.callCount.Add(1)

	// Sleep for random 3-13ms to simulate work and create timing variations
	sleepMs := randomInt(3, 13)
	time.Sleep(time.Duration(sleepMs) * time.Millisecond)

	return &raceTestResponse{
		Processed: true,
		ServerTS:  time.Now().UnixNano(),
	}, nil
}

func (h *raceTestHandler) OnConnect(conn interface{}) {
	// No-op
}

func (h *raceTestHandler) Close() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
}

// randomInt returns a random int in [min, max]
func randomInt(min, max int) int {
	if min >= max {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// TestRaceConcurrentClientOperations tests concurrent operations on a single client
func TestRaceConcurrentClientOperations(t *testing.T) {
	const (
		numGoroutines   = 20
		opsPerGoroutine = 50
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()
	authManager.AuthorizeAll()
	handler := &raceTestHandler{t: t}

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	quicAddr := packetConn.LocalAddr().String()

	serverObs := qmock.NewTestObserver(ctx, t)
	server, err := NewServer(ServerOpt{
		ListenOn:             "",
		ProvisionTokens:      []string{"race-token"},
		Auth:                 authManager,
		Observer:             serverObs,
		RenewalInterval:      5 * time.Millisecond,
		ProvisioningInterval: 5 * time.Millisecond,
		KeepAlivePeriod:      20 * time.Millisecond,
	})
	assertNoError(t, err)
	handler.RegisterHandlers(&server.Router)
	assertNoError(t, server.Serve(ctx, packetConn))
	defer server.Close()

	// Pre-provision client
	id := qdef.Identity{Hostname: "race-single-client"}
	certPEM, keyPEM, err := authManager.IssueClientCertificate(&id, "race-test")
	assertNoError(t, err)

	credStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: id,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
	}

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	clientObs := qmock.NewTestObserver(ctx, t)
	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        clientObs,
		KeepAlivePeriod: 20 * time.Millisecond,
		ResolverRefresh: 10 * time.Millisecond,
	})

	assertNoError(t, client.Connect(ctx))
	defer client.Close()

	// Wait for connection
	time.Sleep(300 * time.Millisecond)

	state := client.state.Current()
	if state != qdef.StateConnected && state != qdef.StateAuthorized {
		t.Skipf("Client not connected (state=%s), skipping concurrent ops test", state)
	}

	var wg sync.WaitGroup

	// Spawn goroutines that all operate on the same client concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(gIdx int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				op := randomInt(0, 4)
				switch op {
				case 0:
					// Send request
					target := qdef.Addr{Service: qdef.ServiceSystem, Type: "race-test"}
					req := &raceTestRequest{GoroutineIdx: gIdx, RequestNum: j}
					var resp raceTestResponse
					reqCtx, reqCancel := context.WithTimeout(ctx, 100*time.Millisecond)
					_, _ = client.Request(reqCtx, target, req, &resp)
					reqCancel()
				case 1:
					// Read state
					_ = client.state.Current()
				case 2:
					// Get identity
					_, _ = credStore.GetIdentity()
				case 3:
					// Set devices
					devices := []qdef.DeviceInfo{{ID: "d1", Name: "D", ServiceType: "t"}}
					client.SetDevices(devices)
				case 4:
					// Update resolver
					resolver.SetAddress(quicAddr)
				}
			}
		}(i)
	}

	wg.Wait()
	t.Log("Concurrent client operations test completed")
}

// TestRaceServerConcurrentConnections tests server handling concurrent connections
func TestRaceServerConcurrentConnections(t *testing.T) {
	const numConnections = 10

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()
	authManager.AuthorizeAll()
	handler := &raceTestHandler{t: t}

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	quicAddr := packetConn.LocalAddr().String()

	serverObs := qmock.NewTestObserver(ctx, t)
	server, err := NewServer(ServerOpt{
		ListenOn:             "",
		ProvisionTokens:      []string{"race-token"},
		Auth:                 authManager,
		Observer:             serverObs,
		RenewalInterval:      5 * time.Millisecond,
		ProvisioningInterval: 5 * time.Millisecond,
	})
	assertNoError(t, err)
	handler.RegisterHandlers(&server.Router)
	assertNoError(t, server.Serve(ctx, packetConn))
	defer server.Close()

	var clients []*Client
	var wg sync.WaitGroup

	// Create and start all clients simultaneously
	for i := 0; i < numConnections; i++ {
		hostname := "race-conn-" + string(rune('a'+i))
		id := qdef.Identity{Hostname: hostname}
		certPEM, keyPEM, err := authManager.IssueClientCertificate(&id, "race-test")
		assertNoError(t, err)

		credStore := &qmock.InMemoryCredentialStore{
			RootCA:   authManager.RootCert(),
			Identity: id,
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
		}

		resolver := &qmock.MockResolver{}
		resolver.SetAddress(quicAddr)

		clientObs := qmock.NewTestObserver(ctx, t)
		client := NewClient(ClientOpt{
			ServerHostname:  testServerHostname,
			CredentialStore: credStore,
			Resolver:        resolver,
			Observer:        clientObs,
			KeepAlivePeriod: 30 * time.Millisecond,
			ResolverRefresh: 20 * time.Millisecond,
		})
		clients = append(clients, client)

		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			if err := c.Connect(ctx); err != nil {
				return
			}

			// Send some requests
			for j := 0; j < 10; j++ {
				target := qdef.Addr{Service: qdef.ServiceSystem, Type: "race-test"}
				req := &raceTestRequest{RequestNum: j}
				var resp raceTestResponse
				reqCtx, reqCancel := context.WithTimeout(ctx, 200*time.Millisecond)
				_, _ = c.Request(reqCtx, target, req, &resp)
				reqCancel()
				time.Sleep(10 * time.Millisecond)
			}
		}(client)
	}

	wg.Wait()

	// Stop all clients
	for _, client := range clients {
		client.Close()
	}

	t.Logf("Concurrent connections test completed with %d clients", numConnections)
}

// TestRacePooledStreams tests concurrent access to the stream pool.
func TestRacePooledStreams(t *testing.T) {
	const (
		numGoroutines      = 30
		requestsPerRoutine = 20
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()
	authManager.AuthorizeAll()
	handler := &raceTestHandler{t: t}

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assertNoError(t, err)
	quicAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		ProvisionTokens:      []string{"race-token"},
		Auth:                 authManager,
		RenewalInterval:      5 * time.Millisecond,
		ProvisioningInterval: 5 * time.Millisecond,
	})
	assertNoError(t, err)
	handler.RegisterHandlers(&server.Router)
	assertNoError(t, server.Serve(ctx, packetConn))
	defer server.Close()

	// Single client with small pool to stress the pool mechanics
	id := qdef.Identity{Hostname: "pool-test-client"}
	certPEM, keyPEM, err := authManager.IssueClientCertificate(&id, "race-test")
	assertNoError(t, err)

	credStore := &qmock.InMemoryCredentialStore{
		RootCA:   authManager.RootCert(),
		Identity: id,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
	}

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(quicAddr)

	client := NewClient(ClientOpt{
		ServerHostname:  testServerHostname,
		CredentialStore: credStore,
		Resolver:        resolver,
		KeepAlivePeriod: 20 * time.Millisecond,
	})

	assertNoError(t, client.Connect(ctx))
	defer client.Close()

	// Wait for connection
	time.Sleep(300 * time.Millisecond)

	state := client.state.Current()
	if state != qdef.StateConnected && state != qdef.StateAuthorized {
		t.Skipf("Client not connected (state=%s), skipping pool test", state)
	}

	var wg sync.WaitGroup
	var successCount atomic.Int64

	// Spawn many goroutines all competing for stream pool
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(gIdx int) {
			defer wg.Done()
			for j := 0; j < requestsPerRoutine; j++ {
				target := qdef.Addr{Service: qdef.ServiceSystem, Type: "race-test"}
				req := &raceTestRequest{GoroutineIdx: gIdx, RequestNum: j}
				var resp raceTestResponse
				reqCtx, reqCancel := context.WithTimeout(ctx, 150*time.Millisecond)
				_, err := client.Request(reqCtx, target, req, &resp)
				reqCancel()
				if err == nil {
					successCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	opens, closes, open := client.StreamStats()
	t.Logf("Stream pool stats: opens=%d, closes=%d, open=%d", opens, closes, open)
	t.Logf("Successful requests: %d/%d", successCount.Load(), int64(numGoroutines*requestsPerRoutine))
}
