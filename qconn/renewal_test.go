package qconn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
)

func TestCertificateRenewal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	auth := qmock.NewInMemoryAuthorizationManager()

	h := qmock.NewTestStreamHandler(t)
	h.Auth = auth
	server, err := NewServer(ServerOpt{
		Auth:            auth,
		ProvisionTokens: []string{"super-secret"},
		Handler:         h,
	})
	if err != nil {
		t.Fatal(err)
	}

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	addr := packetConn.LocalAddr().String()
	go server.Serve(ctx, packetConn)

	// Create a client with a very small renewal window and an already "expiring" cert.
	id := qdef.Identity{Hostname: "client-01"}
	certPEM, keyPEM, _ := auth.IssueClientCertificate(&id)
	auth.SetStatus(id, qdef.StatusAuthorized)

	store := &qmock.InMemoryCredentialStore{
		Identity: id,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		RootCA:   auth.RootCert(),
	}

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(addr)
	client := NewClient(ClientOpt{
		ServerHostname:  "localhost",
		CredentialStore: store,
		Resolver:        resolver,
		RenewWindow:     2 * 365 * 24 * time.Hour, // Very large window to trigger immediately.
		KeepAlivePeriod: 1 * time.Second,          // Speed up checkTicker in supervisor.
	})

	err = client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for connection state to be steady.
	time.Sleep(100 * time.Millisecond)

	// The supervisor should trigger renewal because the window is large.
	originalCert := string(certPEM)

	deadline := time.Now().Add(15 * time.Second)
	success := false
	for time.Now().Before(deadline) {
		var currentCert string
		store.TestingLock(func(s *qmock.InMemoryCredentialStore) {
			currentCert = string(s.CertPEM)
		})
		if currentCert != "" && currentCert != originalCert {
			success = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !success {
		t.Fatal("certificate was not renewed")
	}
}
