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
	server := qconn.NewServer(qconn.ServerOpt{
		Auth:     auth,
		Handler:  hub,
		Listener: hub,
		Observer: qmock.NewTestObserver(ctx, t),
	})

	hub.SetRoleDef("printer-provider", RoleConfig{
		Provides: []string{"printer"},
	})
	// Allow hub itself (no roles in context) to send to any job type?
	// Actually, let's just make it possible to send if no sender roles are present for now,
	// or configure the hub's request to have a role.
	// For simplicity, I'll allow "provide" if no role def exists or if explicitly allowed.

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	addr := "localhost:" + port

	go server.Serve(ctx, packetConn)

	// 3. Setup Provider Client.
	clientID := qdef.Identity{Hostname: "provider-01", Roles: []string{"printer-provider"}}
	clientCertPEM, clientKeyPEM, _ := auth.IssueClientCertificate(&clientID)
	auth.AuthorizeAll()
	hub.SetStaticAuthorization(clientID.Fingerprint, []string{"printer-provider"})

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
		states := hub.ListHostStates()
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

	// 4. Test Routing.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Type:    "printer",
		Machine: fingerprint,
	}

	// 5. Send message via Hub.Request (which simulated a requester)
	var resp PrintResp
	err = hub.Request(ctx, target, &PrintReq{Content: "hello printer"}, &resp)
	if err != nil {
		t.Fatalf("Hub.Request failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected OK=true")
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
