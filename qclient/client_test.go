package qclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"

	"github.com/kardianos/qconn/anex"
	"github.com/kardianos/qconn/qconn"
)

func TestSimpleClientAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var providerID string
	const secretToken = "secret-token"

	// 1. Setup Hub & Server
	hub := anex.NewHub(0)
	auth := qmock.NewInMemoryAuthorizationManager()
	obs := qmock.NewTestObserver(ctx, t)
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth:                 auth,
		Handler:              hub,
		Listener:             hub,
		ProvisionTokens:      []string{secretToken},
		Observer:             obs,
		ProvisioningInterval: 1 * time.Millisecond, // Allow rapid provisioning in tests
	})
	if err != nil {
		t.Fatal(err)
	}
	// Authorize loop in background
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case state := <-obs.States:
				if state == qdef.StateConnected {
					// Authorize all clients regardless for this test.
					// We can just authorize by a "wildcard" if the manager supported it,
					// or just monitor the auth manager's internals if needed.
					// Since we know the hostnames are test-related, we can just
					// set everyone to authorized in our mock.
					auth.AuthorizeAll()
				}
			}
		}
	}()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	serverAddr := "localhost:" + port

	go server.Serve(ctx, packetConn)
	hub.SetRoleDef("requester", anex.RoleConfig{
		SendsTo: []string{"printer", "list-machines"},
	})
	hub.SetRoleDef("provider", anex.RoleConfig{
		Provides: []string{"printer"},
	})

	// 2. Setup Provider
	provDir, _ := os.MkdirTemp("", "qconn-prov-*")
	defer os.RemoveAll(provDir)
	provStore := qmock.NewSimpleFileStore(provDir, "secret-token", "provider-01", "provider")
	provStore.SetRootCA(qdef.EncodeCertPEM(auth.RootCert()))

	provClient := NewClient(serverAddr, provStore)

	type PrintReq struct{ Content string }
	type PrintResp struct{ OK bool }

	_ = Handle(provClient, "printer", StaticDevices("printer"), func(ctx context.Context, id qdef.Identity, req *PrintReq) (*PrintResp, error) {
		t.Logf("Provider received print job: %s", req.Content)
		return &PrintResp{OK: true}, nil
	})

	if err := provClient.Start(ctx); err != nil {
		t.Fatalf("Provider failed to start: %v", err)
	}

	// Wait briefly to avoid provisioning race with requester.
	time.Sleep(100 * time.Millisecond)

	// 3. Setup Requester
	reqDir, _ := os.MkdirTemp("", "qconn-req-*")
	defer os.RemoveAll(reqDir)
	reqStore := qmock.NewSimpleFileStore(reqDir, secretToken, "requester-01", "requester")
	reqStore.SetRootCA(qdef.EncodeCertPEM(auth.RootCert()))

	reqClient := NewClient(serverAddr, reqStore)
	if err := reqClient.Start(ctx); err != nil {
		t.Fatalf("Requester failed to start: %v", err)
	}

	// 4. Wait for both clients to connect and discover their fingerprints.
	var requesterFP, providerFP qdef.FP
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		states := hub.ListHostStates(false)
		for _, s := range states {
			if s.Identity.Hostname == "requester-01" && s.Online {
				requesterFP = s.Identity.Fingerprint
			}
			if s.Identity.Hostname == "provider-01" && s.Online && len(s.Identity.Devices) > 0 {
				providerFP = s.Identity.Fingerprint
				providerID = providerFP.String()
			}
		}
		if !requesterFP.IsZero() && !providerFP.IsZero() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if requesterFP.IsZero() || providerFP.IsZero() {
		t.Fatalf("clients did not connect in time (requester: %v, provider: %v)", !requesterFP.IsZero(), !providerFP.IsZero())
	}

	// Set up role authorization now that we know the fingerprints.
	hub.SetStaticAuthorization(requesterFP.String(), []string{"requester"})
	hub.SetStaticAuthorization(providerFP.String(), []string{"provider"})
	hub.OnStateChange(qdef.Identity{Fingerprint: requesterFP, Hostname: "requester-01"}, qdef.StateAuthorized)
	hub.OnStateChange(qdef.Identity{Fingerprint: providerFP, Hostname: "provider-01"}, qdef.StateAuthorized)

	// 5. Test Discovery
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		hosts, err := reqClient.ListMachines(ctx, false)
		if err == nil {
			for _, h := range hosts {
				for _, d := range h.Identity.Devices {
					if d == "printer" {
						providerID = h.Identity.Fingerprint.String()
						break
					}
				}
			}
		}
		if providerID != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if providerID == "" {
		t.Fatal("could not discover printer device")
	}

	// Call the printer.
	target := qdef.Addr{
		Machine: providerID,
		Type:    "printer",
	}
	resp, err := Request[PrintReq, PrintResp](reqClient, ctx, target, &PrintReq{Content: "Hello World"})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if !resp.OK {
		t.Fatal("expected OK response")
	}
}

func TestDeviceProviders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hub := anex.NewHub(0)
	auth := qmock.NewInMemoryAuthorizationManager()
	obs := qmock.NewTestObserver(ctx, t)
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth:     auth,
		Handler:  hub,
		Listener: hub,
		Observer: obs,
	})
	if err != nil {
		t.Fatal(err)
	}
	packetConn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	serverAddr := "localhost:" + port
	go server.Serve(ctx, packetConn)

	// Register hub handlers on the server router.
	hub.RegisterHandlers(&server.Router)

	// Set up role that allows list-machines.
	hub.SetRoleDef("device-provider", anex.RoleConfig{
		SendsTo: []string{"list-machines"},
	})

	provID := qdef.Identity{Hostname: "provider-timer"}
	certPEM, keyPEM, _ := auth.IssueClientCertificate(&provID)
	store := &mockCredentialStore{
		id:         provID,
		certPEM:    certPEM,
		keyPEM:     keyPEM,
		rootCACert: auth.RootCert(),
	}

	// Set up authorization for this client's fingerprint.
	hub.SetStaticAuthorization(provID.Fingerprint.String(), []string{"device-provider"})
	auth.AuthorizeAll()

	client := NewClient(serverAddr, store)

	// 1. Static Provider
	client.SetDeviceProvider("static", StaticDevices("dev1", "dev2"))

	// 2. Timer Provider
	dynamicDevices := []string{"dyn1"}
	var mu sync.Mutex
	client.SetDeviceProvider("timer", TimerDevices(500*time.Millisecond, func(ctx context.Context) []string {
		mu.Lock()
		defer mu.Unlock()
		return dynamicDevices
	}))

	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// 3. Verify initial devices
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		hosts, _ := client.ListMachines(ctx, false)
		for _, h := range hosts {
			if h.Online {
				devs := h.Identity.Devices
				found1, found2, found3 := false, false, false
				for _, d := range devs {
					if d == "dev1" {
						found1 = true
					}
					if d == "dev2" {
						found2 = true
					}
					if d == "dyn1" {
						found3 = true
					}
				}
				if found1 && found2 && found3 {
					goto step4
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("failed to see initial devices")

step4:
	// 4. Update dynamic devices and verify timer refresh
	mu.Lock()
	dynamicDevices = []string{"dyn1", "dyn2"}
	mu.Unlock()

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		hosts, _ := client.ListMachines(ctx, false)
		for _, h := range hosts {
			if h.Online {
				found := false
				for _, d := range h.Identity.Devices {
					if d == "dyn2" {
						found = true
						break
					}
				}
				if found {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("failed to see updated dynamic devices")
}

type mockCredentialStore struct {
	id         qdef.Identity
	certPEM    []byte
	keyPEM     []byte
	rootCACert *x509.Certificate
}

func (s *mockCredentialStore) GetIdentity() (qdef.Identity, error) { return s.id, nil }
func (s *mockCredentialStore) ProvisionToken() string              { return "" }
func (s *mockCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(s.certPEM, s.keyPEM)
}
func (s *mockCredentialStore) GetRootCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AddCert(s.rootCACert)
	return pool, nil
}
func (s *mockCredentialStore) SaveCredentials(id qdef.Identity, certPEM, keyPEM []byte) error {
	s.id, s.certPEM, s.keyPEM = id, certPEM, keyPEM
	return nil
}
func (s *mockCredentialStore) OnUpdate() <-chan struct{} { return nil }

type mockResolver struct {
	addr string
}

func (r *mockResolver) Resolve(ctx context.Context, hostname string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", r.addr)
}
func (r *mockResolver) OnUpdate(hostname string) <-chan struct{} { return nil }
