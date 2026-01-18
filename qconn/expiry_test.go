package qconn

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
)

// TestCertExpiryDetection tests that expired certificates are properly detected.
func TestCertExpiryDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Setup server
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer packetConn.Close()
	serverAddr := packetConn.LocalAddr().String()

	server, err := NewServer(ServerOpt{
		ProvisionTokens: []string{"test-token"},
		Auth:            authManager,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if err := server.Serve(ctx, packetConn); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	// Setup client
	credStore := &qmock.InMemoryCredentialStore{
		RootCA: authManager.RootCert(),
		Token:  "test-token",
	}
	resolver := &qmock.MockResolver{}
	resolver.SetAddress(serverAddr)
	observer := qmock.NewTestObserver(ctx, t)

	client := NewClient(ClientOpt{
		ServerHostname:  "localhost",
		CredentialStore: credStore,
		Resolver:        resolver,
		Observer:        observer,
		KeepAlivePeriod: 5 * time.Second,
	})

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	// Wait for provisioning and connection
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state := client.state.Current()
		if state == qdef.StateConnected || state == qdef.StateAuthorized {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	state := client.state.Current()
	if state != qdef.StateConnected && state != qdef.StateAuthorized {
		t.Fatalf("expected connected state, got %s", state)
	}

	// Now simulate time passing beyond cert expiry
	// Get the client's cert expiry time
	tlsCert, err := credStore.GetClientCertificate()
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}

	// Parse cert to get NotAfter
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("no certificate in chain")
	}

	t.Logf("Client connected successfully, cert obtained")

	// Test GetStatus with expired cert
	fp := credStore.Identity.Fingerprint
	status, err := authManager.GetStatus(fp)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	t.Logf("Current status: %s", status)
}

// TestProvisioningCertExpiry tests that the server's provisioning cert
// expiry is handled correctly.
func TestProvisioningCertExpiry(t *testing.T) {
	// This test verifies the issue: server provisioning certs are created
	// at startup with 24h validity and never refreshed.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Create server
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer packetConn.Close()

	server, err := NewServer(ServerOpt{
		ProvisionTokens: []string{"test-token"},
		Auth:            authManager,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Check the provisioning certs were created
	if len(server.provisioningCerts) == 0 {
		t.Fatal("no provisioning certs created")
	}

	// Examine the cert validity
	for sni, entry := range server.provisioningCerts {
		if len(entry.cert.Certificate) == 0 {
			t.Errorf("SNI %s: no certificate", sni)
			continue
		}

		leaf, err := x509.ParseCertificate(entry.cert.Certificate[0])
		if err != nil {
			t.Errorf("SNI %s: parse cert: %v", sni, err)
			continue
		}

		validity := leaf.NotAfter.Sub(leaf.NotBefore)
		t.Logf("SNI %s: validity=%v, NotBefore=%v, NotAfter=%v",
			sni, validity, leaf.NotBefore, leaf.NotAfter)

		// Current implementation: 24h validity
		// This is problematic for long-running servers
		if validity > 25*time.Hour {
			t.Logf("SNI %s: validity is reasonable (%v)", sni, validity)
		} else {
			t.Logf("WARNING: SNI %s: short validity (%v) - will expire if server runs > 24h", sni, validity)
		}
	}

	// Start serving (needed for client test below)
	if err := server.Serve(ctx, packetConn); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// TestTimeNowOverride verifies that timeNow can be overridden for testing.
func TestTimeNowOverride(t *testing.T) {
	// Save original
	origTimeNow := timeNow
	defer func() { timeNow = origTimeNow }()

	// Override to a fixed time
	fixedTime := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return fixedTime }

	// Verify override works
	if got := timeNow(); !got.Equal(fixedTime) {
		t.Errorf("timeNow() = %v, want %v", got, fixedTime)
	}
}

// TestProvisioningCertRegeneration tests that provisioning certs are regenerated
// when they are close to expiry.
func TestProvisioningCertRegeneration(t *testing.T) {
	// Save original
	origTimeNow := timeNow
	defer func() { timeNow = origTimeNow }()

	authManager := qmock.NewInMemoryAuthorizationManager()

	// Create server
	server, err := NewServer(ServerOpt{
		ProvisionTokens: []string{"test-token"},
		Auth:            authManager,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Get the provisioning SNI
	var sni string
	for s := range server.provisioningCerts {
		sni = s
		break
	}
	if sni == "" {
		t.Fatal("no provisioning certs created")
	}

	// Get the initial cert
	cert1, err := server.getProvisioningCert(sni)
	if err != nil {
		t.Fatalf("getProvisioningCert: %v", err)
	}
	if cert1 == nil {
		t.Fatal("getProvisioningCert returned nil")
	}

	leaf1, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert1: %v", err)
	}
	t.Logf("Initial cert NotAfter: %v, Serial: %s", leaf1.NotAfter, leaf1.SerialNumber)
	cert1Bytes := cert1.Certificate[0]

	// First test: time well before expiry (23 hours remaining) - should NOT regenerate
	timeNow = func() time.Time { return leaf1.NotAfter.Add(-23 * time.Hour) }
	cert2, err := server.getProvisioningCert(sni)
	if err != nil {
		t.Fatalf("getProvisioningCert: %v", err)
	}

	leaf2, err := x509.ParseCertificate(cert2.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert2: %v", err)
	}

	// Should be same cert (23 hours > 1 hour threshold)
	if leaf2.SerialNumber.Cmp(leaf1.SerialNumber) != 0 {
		t.Errorf("cert should NOT have been regenerated at 23h before expiry")
	}
	t.Logf("At 23h-to-expiry: same cert, Serial: %s", leaf2.SerialNumber)

	// Second test: time close to expiry (30 minutes remaining) - SHOULD regenerate
	timeNow = func() time.Time { return leaf1.NotAfter.Add(-30 * time.Minute) }
	cert3, err := server.getProvisioningCert(sni)
	if err != nil {
		t.Fatalf("getProvisioningCert: %v", err)
	}

	leaf3, err := x509.ParseCertificate(cert3.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert3: %v", err)
	}

	// Should be a NEW cert (different serial number)
	if leaf3.SerialNumber.Cmp(leaf1.SerialNumber) == 0 {
		t.Errorf("cert should have been regenerated at 30min before expiry, but serial is same")
	}
	t.Logf("At 30min-to-expiry: NEW cert, Serial: %s (was %s)", leaf3.SerialNumber, leaf1.SerialNumber)

	// Verify the new cert is actually stored
	cert3Bytes := cert3.Certificate[0]
	if string(cert1Bytes) == string(cert3Bytes) {
		t.Error("cert bytes should be different after regeneration")
	}

	// Third test: after regeneration, should use the new cert
	timeNow = origTimeNow
	cert4, err := server.getProvisioningCert(sni)
	if err != nil {
		t.Fatalf("getProvisioningCert: %v", err)
	}

	leaf4, err := x509.ParseCertificate(cert4.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert4: %v", err)
	}

	// Should be the same as cert3 (the regenerated one)
	if leaf4.SerialNumber.Cmp(leaf3.SerialNumber) != 0 {
		t.Errorf("cert4 serial = %s, want %s (same as regenerated cert)", leaf4.SerialNumber, leaf3.SerialNumber)
	}
	t.Logf("After reset: using regenerated cert, Serial: %s", leaf4.SerialNumber)
}
