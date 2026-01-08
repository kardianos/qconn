package anex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qclient"
	"github.com/kardianos/qconn/qconn"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
	"github.com/quic-go/quic-go"
)

func TestAnexRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Setup Hub.
	hub := NewHub(0)

	// 2. Setup QC Server.
	auth := qmock.NewInMemoryAuthorizationManager()
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth:     auth,
		Handler:  hub,
		Listener: hub,
		Observer: qmock.NewTestObserver(ctx, t),
	})
	if err != nil {
		t.Fatal(err)
	}

	hub.SetRoleDef("printer-provider", RoleConfig{
		Provides: []string{"printer"},
	})
	hub.SetRoleDef("print-requester", RoleConfig{
		SendsTo: []string{"printer"},
	})

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	addr := "localhost:" + port

	go server.Serve(ctx, packetConn)

	// 3. Setup Provider Client.
	clientID := qdef.Identity{Hostname: "provider-01"}
	clientCertPEM, clientKeyPEM, _ := auth.IssueClientCertificate(&clientID)
	auth.AuthorizeAll()

	provStore := &mockCredentialStore{
		id:         clientID,
		certPEM:    clientCertPEM,
		keyPEM:     clientKeyPEM,
		rootCACert: auth.RootCert(),
	}

	provClient := qclient.NewClient(addr, provStore)

	type PrintReq struct{ Content string }
	type PrintResp struct{ OK bool }

	_ = qclient.Handle(provClient, "printer", qclient.StaticDevices("printer"), func(ctx context.Context, id qdef.Identity, req *PrintReq) (*PrintResp, error) {
		return &PrintResp{OK: true}, nil
	})

	if err := provClient.Start(ctx); err != nil {
		t.Fatalf("Provider failed to start: %v", err)
	}

	// Wait for connection and device registration.
	fingerprint := ""
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		states := hub.ListHostStates(false)
		for _, s := range states {
			if s.Identity.Hostname == "provider-01" && s.Online && len(s.Identity.Devices) > 0 {
				fingerprint = s.Identity.Fingerprint
				break
			}
		}
		if fingerprint != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if fingerprint == "" {
		t.Fatal("provider client did not register devices in time")
	}

	// Now that we know the fingerprint, set up role authorization and re-trigger state change.
	hub.SetStaticAuthorization(fingerprint, []string{"printer-provider"})
	hub.OnStateChange(qdef.Identity{Fingerprint: fingerprint, Hostname: "provider-01"}, qdef.StateAuthorized)

	// 4. Test Routing.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Type:    "printer",
		Machine: fingerprint,
	}

	// 5. Send message via Hub.Request (which simulates a requester)
	// Use a different identity with requester role.
	requesterID := qdef.Identity{
		Hostname:    "requester-01",
		Fingerprint: "fake-requester-fp",
		Roles:       []string{"print-requester"},
	}
	var resp PrintResp
	err = hub.Request(ctx, requesterID, target, &PrintReq{Content: "hello printer"}, &resp)
	if err != nil {
		t.Fatalf("Hub.Request failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected OK=true")
	}
}

func TestProvisionedUnprovisioned(t *testing.T) {
	ctx := context.Background()

	hub := NewHub(0)

	// Set up admin role that can call list-machines and provision.
	hub.SetRoleDef("admin", RoleConfig{
		SendsTo: []string{"list-machines", "provision"},
	})
	adminID := qdef.Identity{
		Hostname:    "admin",
		Fingerprint: "admin-fp",
		Roles:       []string{"admin"},
	}

	// Add unprovisioned
	hub.unprovisioned["machine-alpha"] = struct{}{}
	hub.unprovisioned["machine-beta"] = struct{}{}

	// List with unprovisioned
	resp, err := hub.handleListMachines(ctx, adminID, &qdef.ListMachinesReq{ShowUnprovisioned: true})
	if err != nil {
		t.Fatalf("list machines: %v", err)
	}
	if len(resp.Hosts) != 2 {
		t.Errorf("expected 2 unprovisioned hosts, got %d", len(resp.Hosts))
	}
	for _, h := range resp.Hosts {
		if h.Provisioned {
			t.Errorf("expected unprovisioned host, got provisioned: %v", h)
		}
	}

	// Provision one
	provReq := &qdef.ProvisionReq{Fingerprint: []string{"machine-alpha"}}
	_, err = hub.handleProvision(ctx, adminID, provReq)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	// Check lists - without unprovisioned flag should show nothing (no connected hosts)
	resp2, err := hub.handleListMachines(ctx, adminID, &qdef.ListMachinesReq{ShowUnprovisioned: false})
	if err != nil {
		t.Fatalf("list machines: %v", err)
	}
	if len(resp2.Hosts) != 0 {
		t.Errorf("expected 0 provisioned hosts (none connected), got %d", len(resp2.Hosts))
	}

	// With unprovisioned flag should show only machine-beta now
	resp3, err := hub.handleListMachines(ctx, adminID, &qdef.ListMachinesReq{ShowUnprovisioned: true})
	if err != nil {
		t.Fatalf("list machines: %v", err)
	}
	if len(resp3.Hosts) != 1 {
		t.Errorf("expected 1 unprovisioned host, got %d", len(resp3.Hosts))
	}
	if resp3.Hosts[0].Identity.Hostname != "machine-beta" {
		t.Errorf("expected machine-beta got %v", resp3.Hosts[0].Identity.Hostname)
	}
}

// --- Mocks ---

type mockStreamHandler struct {
	t        *testing.T
	received chan qdef.Message
}

func (m *mockStreamHandler) Handle(ctx context.Context, id qdef.Identity, msg qdef.Message, stream qdef.Stream) {
	if msg.Target.Service != qdef.ServiceSystem { // Ignore system messages like devices update if they leak here
		m.received <- qdef.Message(msg)
		// Send response.
		raw, _ := cbor.Marshal("ok")
		resp := qdef.Message{
			ID:      msg.ID,
			Payload: raw,
		}
		cbor.NewEncoder(stream).Encode(resp)
	}
}
func (m *mockStreamHandler) OnConnect(conn *quic.Conn) {}

type mockCredentialStore struct {
	id         qdef.Identity
	certPEM    []byte
	keyPEM     []byte
	rootCACert *x509.Certificate
	token      string
}

func (s *mockCredentialStore) GetIdentity() (qdef.Identity, error) { return s.id, nil }
func (s *mockCredentialStore) ProvisionToken() string              { return s.token }
func (s *mockCredentialStore) GetClientCertificate() (tls.Certificate, error) {
	if len(s.certPEM) == 0 {
		return tls.Certificate{}, qdef.ErrCredentialsMissing
	}
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
