package qmanage_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kardianos/qconn/qconn"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmanage"
	"github.com/kardianos/qconn/qmock"
	"go.etcd.io/bbolt"
)

func TestClientStoreOperations(t *testing.T) {
	dir := t.TempDir()

	// Create store with identity and token set at initialization.
	cfg := qmanage.ClientStoreConfig{
		Dir:            dir,
		Hostname:       "test-host",
		Roles:          []string{"worker"},
		ProvisionToken: "test-token-123",
	}
	store, err := qmanage.NewClientStoreWithDir(cfg)
	if err != nil {
		t.Fatalf("NewClientStoreWithDir: %v", err)
	}
	defer store.Close()

	// Test initial state - hostname and roles from config.
	id, err := store.GetIdentity()
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if id.Hostname != "test-host" {
		t.Errorf("expected hostname 'test-host', got %q", id.Hostname)
	}

	// Test ProvisionToken returns the token from config.
	if token := store.ProvisionToken(); token != "test-token-123" {
		t.Errorf("expected token 'test-token-123', got %q", token)
	}

	// Test SetRootCA and GetRootCAs.
	ca, _ := qmock.NewInMemoryCA()
	caPEM := qdef.EncodeCertPEM(ca.RootCert())
	if err := store.SetRootCA(caPEM); err != nil {
		t.Fatalf("SetRootCA: %v", err)
	}
	pool, err := store.GetRootCAs()
	if err != nil {
		t.Fatalf("GetRootCAs: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil cert pool")
	}

	// Test SaveCredentials and GetClientCertificate.
	testID := qdef.Identity{Hostname: "test-host", Roles: []string{"worker"}}
	certPEM, keyPEM, err := ca.IssueClientCertificate(testID)
	if err != nil {
		t.Fatalf("IssueClientCertificate: %v", err)
	}

	// Setup update channel before save.
	updateCh := store.OnUpdate()

	if err := store.SaveCredentials(certPEM, keyPEM); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	// Check signal was triggered.
	select {
	case <-updateCh:
		// Good.
	case <-time.After(100 * time.Millisecond):
		t.Error("expected update signal")
	}

	// Test GetClientCertificate.
	cert, err := store.GetClientCertificate()
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("expected non-empty certificate")
	}

	// Test GetIdentity after save.
	savedID, err := store.GetIdentity()
	if err != nil {
		t.Fatalf("GetIdentity after save: %v", err)
	}
	if savedID.Hostname != "test-host" {
		t.Errorf("expected hostname 'test-host', got %q", savedID.Hostname)
	}
	if savedID.Fingerprint.IsZero() {
		t.Error("expected fingerprint to be set")
	}
}

func TestAuthManagerOperations(t *testing.T) {
	dir := t.TempDir()

	cfg := qmanage.AuthManagerConfig{
		AppName: "test",
		DataDir: dir,
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Test RootCert.
	if auth.RootCert() == nil {
		t.Fatal("expected non-nil root cert")
	}

	// Test client status via provisioning.
	csrPEM, _, err := qdef.CreateCSR("test-client")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client", []string{"worker"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	fp := qdef.FingerprintOf(leaf)

	if err := auth.SetClientStatus(fp, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus: %v", err)
	}

	clients := auth.ListClients(qmanage.ClientFilter{})
	if len(clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(clients))
	}
	if clients[fp].Status != qdef.StatusAuthorized {
		t.Errorf("expected StatusAuthorized, got %v", clients[fp].Status)
	}

	// Test ServerCertificate.
	serverCert, err := auth.ServerCertificate()
	if err != nil {
		t.Fatalf("ServerCertificate: %v", err)
	}
	if len(serverCert.Certificate) == 0 {
		t.Error("expected non-empty server certificate")
	}
}

func TestProvisioningCSR(t *testing.T) {
	dir := t.TempDir()

	cfg := qmanage.AuthManagerConfig{
		AppName: "test",
		DataDir: dir,
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create CSR.
	csrPEM, _, err := qdef.CreateCSR("test-client")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}

	// Sign provisioning CSR.
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client", nil)
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	// Verify certificate.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if leaf.Subject.CommonName != "test-client" {
		t.Errorf("expected CN 'test-client', got %q", leaf.Subject.CommonName)
	}

	// Verify client was tracked.
	fp := qdef.FingerprintOf(leaf)
	status, err := auth.GetStatus(fp)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != qdef.StatusUnauthorized {
		t.Errorf("expected StatusUnauthorized, got %v", status)
	}

	clients := auth.ListClients(qmanage.ClientFilter{})
	if _, ok := clients[fp]; !ok {
		t.Error("expected client to be tracked")
	}
}

func TestRenewalCSR(t *testing.T) {
	dir := t.TempDir()

	cfg := qmanage.AuthManagerConfig{
		AppName: "test",
		DataDir: dir,
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create and sign initial CSR.
	csrPEM, _, err := qdef.CreateCSR("test-client")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client", nil)
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	// Get fingerprint.
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	oldFP := qdef.FingerprintOf(leaf)

	// Authorize the client.
	if err := auth.SetClientStatus(oldFP, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus: %v", err)
	}

	// Create renewal CSR.
	renewCSRPEM, _, err := qdef.CreateCSR("test-client")
	if err != nil {
		t.Fatalf("CreateCSR for renewal: %v", err)
	}

	// Sign renewal CSR.
	newCertPEM, err := auth.SignRenewalCSR(renewCSRPEM, oldFP)
	if err != nil {
		t.Fatalf("SignRenewalCSR: %v", err)
	}

	// Get new fingerprint.
	block, _ = pem.Decode(newCertPEM)
	newLeaf, _ := x509.ParseCertificate(block.Bytes)
	newFP := qdef.FingerprintOf(newLeaf)

	if newFP == oldFP {
		t.Error("expected different fingerprint after renewal")
	}

	// Verify status was preserved.
	status, err := auth.GetStatus(newFP)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != qdef.StatusAuthorized {
		t.Errorf("expected StatusAuthorized after renewal, got %v", status)
	}

	// Verify old fingerprint was removed.
	clients := auth.ListClients(qmanage.ClientFilter{Fingerprints: []qdef.FP{oldFP}})
	if len(clients) != 0 {
		t.Errorf("expected old fingerprint to be removed")
	}
}

func TestFullIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup server auth manager.
	serverDir := t.TempDir()
	authCfg := qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         serverDir,
		ServerHostname:  "localhost",
		CleanupInterval: -1,
	}
	authMgr, err := qmanage.NewAuthManager(authCfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer authMgr.Close()

	// Setup server with built-in role management.
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth:     authMgr,
		Observer: qmock.NewTestObserver(ctx, t),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	server.SetRoleDef("printer-provider", qdef.RoleConfig{
		Provides: []string{"printer"},
	})
	server.SetRoleDef("print-requester", qdef.RoleConfig{
		SendsTo: []string{"printer"},
	})

	// Start server.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()

	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	addr := "localhost:" + port

	go server.Serve(ctx, packetConn)

	// Create provider client using CSR flow (with roles).
	providerID := qdef.Identity{Hostname: "provider-01"}
	providerCSRPEM, providerKeyPEM, err := qdef.CreateCSR("provider-01")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	providerCertPEM, err := authMgr.SignProvisioningCSR(providerCSRPEM, "provider-01", []string{"printer-provider"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	// Extract fingerprint from cert.
	block, _ := pem.Decode(providerCertPEM)
	if block != nil {
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if leaf != nil {
			providerID.Fingerprint = qdef.FingerprintOf(leaf)
		}
	}

	// Authorize provider.
	authMgr.SetClientStatus(providerID.Fingerprint, qdef.StatusAuthorized)

	provStore := &mockCredentialStore{
		id:         providerID,
		certPEM:    providerCertPEM,
		keyPEM:     providerKeyPEM,
		rootCACert: authMgr.RootCert(),
	}

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(addr)

	provClient := qconn.NewClient(qconn.ClientOpt{
		ServerHostname:  "localhost",
		CredentialStore: provStore,
		Resolver:        resolver,
	})

	type PrintReq struct{ Content string }
	type PrintResp struct{ OK bool }

	qdef.Handle(&provClient.Router, qdef.ServiceUser, "printer", func(ctx context.Context, id qdef.Identity, req *PrintReq) (*PrintResp, error) {
		t.Logf("Provider received print request: %s", req.Content)
		return &PrintResp{OK: true}, nil
	})

	if err := provClient.Connect(ctx); err != nil {
		t.Fatalf("Provider connect: %v", err)
	}
	defer provClient.Close()

	// Wait for provider to connect.
	deadline := time.Now().Add(5 * time.Second)
	providerOnline := false
	for time.Now().Before(deadline) {
		clients := authMgr.ListClientsInfo(true, nil)
		for _, c := range clients {
			if c.Hostname == "provider-01" && c.Online {
				providerOnline = true
				break
			}
		}
		if providerOnline {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !providerOnline {
		t.Fatal("provider did not come online in time")
	}

	// Create requester client (with roles).
	requesterID := qdef.Identity{Hostname: "requester-01"}
	csrPEM, requesterKeyPEM, err := qdef.CreateCSR("requester-01")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	requesterCertPEM, err := authMgr.SignProvisioningCSR(csrPEM, "requester-01", []string{"print-requester"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	block, _ = pem.Decode(requesterCertPEM)
	if block != nil {
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if leaf != nil {
			requesterID.Fingerprint = qdef.FingerprintOf(leaf)
		}
	}

	// Authorize requester.
	authMgr.SetClientStatus(requesterID.Fingerprint, qdef.StatusAuthorized)

	reqStore := &mockCredentialStore{
		id:         requesterID,
		certPEM:    requesterCertPEM,
		keyPEM:     requesterKeyPEM,
		rootCACert: authMgr.RootCert(),
	}

	reqResolver := &qmock.MockResolver{}
	reqResolver.SetAddress(addr)

	reqClient := qconn.NewClient(qconn.ClientOpt{
		ServerHostname:  "localhost",
		CredentialStore: reqStore,
		Resolver:        reqResolver,
	})
	if err := reqClient.Connect(ctx); err != nil {
		t.Fatalf("Requester connect: %v", err)
	}
	defer reqClient.Close()

	// Wait for requester to connect.
	deadline = time.Now().Add(5 * time.Second)
	requesterOnline := false
	for time.Now().Before(deadline) {
		clients := authMgr.ListClientsInfo(true, nil)
		for _, c := range clients {
			if c.Hostname == "requester-01" && c.Online {
				requesterOnline = true
				break
			}
		}
		if requesterOnline {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !requesterOnline {
		t.Fatal("requester did not come online in time")
	}

	// Send print request.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Type:    "printer",
		Machine: providerID.Fingerprint,
	}

	var resp PrintResp
	_, err = reqClient.Request(ctx, target, &PrintReq{Content: "Hello from test"}, &resp)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !resp.OK {
		t.Error("expected OK=true in response")
	}

	t.Log("Full integration test passed")
}

func TestRevocation(t *testing.T) {
	dir := t.TempDir()

	cfg := qmanage.AuthManagerConfig{
		AppName: "test",
		DataDir: dir,
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create and authorize a client.
	csrPEM, _, err := qdef.CreateCSR("test-client")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client", nil)
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	fp := qdef.FingerprintOf(leaf)

	auth.SetClientStatus(fp, qdef.StatusAuthorized)

	// Revoke the client.
	if err := auth.SetClientStatus(fp, qdef.StatusRevoked); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Verify status.
	status, err := auth.GetStatus(fp)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != qdef.StatusRevoked {
		t.Errorf("expected StatusRevoked, got %v", status)
	}

	// Verify renewal fails.
	newCSRPEM, _, _ := qdef.CreateCSR("test-client")
	_, err = auth.SignRenewalCSR(newCSRPEM, fp)
	if err != qdef.ErrClientRevoked {
		t.Errorf("expected ErrClientRevoked, got %v", err)
	}
}

func TestWaitFor(t *testing.T) {
	dir := t.TempDir()

	cfg := qmanage.AuthManagerConfig{
		AppName: "test",
		DataDir: dir,
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create a client.
	csrPEM, _, err := qdef.CreateCSR("test-client")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client", nil)
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	fp := qdef.FingerprintOf(leaf)

	// Change status in goroutine.
	go func() {
		time.Sleep(50 * time.Millisecond)
		auth.SetClientStatus(fp, qdef.StatusAuthorized)
	}()

	// Wait for status change.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := auth.WaitFor(ctx, fp); err != nil {
		t.Errorf("WaitFor returned error: %v", err)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	// Create and populate auth manager.
	cfg := qmanage.AuthManagerConfig{
		AppName: "test",
		DataDir: dir,
	}
	auth1, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	// Add some data and authorize the client (unauthorized clients are memory-only).
	csrPEM, _, _ := qdef.CreateCSR("test-client")
	certPEM, _ := auth1.SignProvisioningCSR(csrPEM, "test-client", []string{"worker"})
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	fp := qdef.FingerprintOf(leaf)
	auth1.SetClientStatus(fp, qdef.StatusAuthorized)

	caCert := auth1.RootCert()
	auth1.Close()

	// Reopen and verify data persisted.
	auth2, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager (reopen): %v", err)
	}
	defer auth2.Close()

	// CA should be the same.
	if qdef.FingerprintOf(auth2.RootCert()) != qdef.FingerprintOf(caCert) {
		t.Error("CA fingerprint changed after reopen")
	}

	// Client should be present.
	clients := auth2.ListClients(qmanage.ClientFilter{})
	if len(clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(clients))
	}
}

func TestBackup(t *testing.T) {
	dir := t.TempDir()

	// Create auth manager with backup disabled (we'll call Backup manually).
	cfg := qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         dir,
		CleanupInterval: -1,
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	// Add some data.
	csrPEM, _, err := qdef.CreateCSR("backup-client")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "backup-client", []string{"worker"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	clientFP := qdef.FingerprintOf(leaf)

	// Authorize the client.
	auth.SetClientStatus(clientFP, qdef.StatusAuthorized)

	// Create backup.
	if err := auth.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Verify backup file exists.
	backupPath := filepath.Join(dir, "auth.db.backup")
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("backup file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("backup file is empty")
	}

	// Close original and open backup to verify contents.
	auth.Close()

	// Open backup database directly.
	backupDB, err := bbolt.Open(backupPath, 0600, &bbolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer backupDB.Close()

	// Verify client exists in backup.
	err = backupDB.View(func(tx *bbolt.Tx) error {
		clientsBucket := tx.Bucket([]byte("clients"))
		if clientsBucket == nil {
			return fmt.Errorf("clients bucket not found")
		}
		if clientsBucket.Get(clientFP[:]) == nil {
			return fmt.Errorf("client not found in backup")
		}
		return nil
	})
	if err != nil {
		t.Errorf("verify backup clients: %v", err)
	}
}

func TestCleanupExpiredClients(t *testing.T) {
	dir := t.TempDir()

	// Create auth manager with cleanup disabled.
	cfg := qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         dir,
		CleanupInterval: -1, // Disable automatic cleanup.
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create 3 clients.
	var fingerprints []qdef.FP
	for i := 0; i < 3; i++ {
		hostname := "client-" + string(rune('a'+i))
		csrPEM, _, err := qdef.CreateCSR(hostname)
		if err != nil {
			t.Fatalf("CreateCSR: %v", err)
		}
		certPEM, err := auth.SignProvisioningCSR(csrPEM, hostname, []string{"worker"})
		if err != nil {
			t.Fatalf("SignProvisioningCSR: %v", err)
		}

		block, _ := pem.Decode(certPEM)
		leaf, _ := x509.ParseCertificate(block.Bytes)
		fingerprints = append(fingerprints, qdef.FingerprintOf(leaf))
	}

	// Authorize all clients.
	for _, fp := range fingerprints {
		auth.SetClientStatus(fp, qdef.StatusAuthorized)
	}

	// Set expiry for first two clients to be in the past.
	pastTime := time.Now().Add(-24 * time.Hour)
	if err := auth.SetClientExpiry(fingerprints[0], pastTime); err != nil {
		t.Fatalf("SetClientExpiry: %v", err)
	}
	if err := auth.SetClientExpiry(fingerprints[1], pastTime); err != nil {
		t.Fatalf("SetClientExpiry: %v", err)
	}

	// Verify all 3 clients exist.
	clients := auth.ListClients(qmanage.ClientFilter{})
	if len(clients) != 3 {
		t.Fatalf("expected 3 clients, got %d", len(clients))
	}

	// Run cleanup.
	removed, err := auth.CleanupExpiredClients()
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if removed != 2 {
		t.Errorf("expected 2 clients removed, got %d", removed)
	}

	// Verify only the non-expired client remains.
	clients = auth.ListClients(qmanage.ClientFilter{})
	if len(clients) != 1 {
		t.Errorf("expected 1 client remaining, got %d", len(clients))
	}

	// Verify the right client remains.
	if _, ok := clients[fingerprints[2]]; !ok {
		t.Error("expected non-expired client to remain")
	}

	// Verify non-expired client's roles remain.
	client := clients[fingerprints[2]]
	if len(client.RequestedRoles) != 1 || client.RequestedRoles[0] != "worker" {
		t.Errorf("expected non-expired client to have worker role, got %v", client.RequestedRoles)
	}
}

func TestUpdateClientAddr(t *testing.T) {
	dir := t.TempDir()

	cfg := qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         dir,
		CleanupInterval: -1,
	}
	auth, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create a client.
	csrPEM, _, err := qdef.CreateCSR("test-client")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client", nil)
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	fp := qdef.FingerprintOf(leaf)

	// Initially LastAddr should be zero value.
	clients := auth.ListClients(qmanage.ClientFilter{})
	if clients[fp].LastAddr.IsValid() {
		t.Errorf("expected zero LastAddr, got %v", clients[fp].LastAddr)
	}

	// Update the address.
	testAddr := netip.MustParseAddrPort("192.168.1.100:54321")
	if err := auth.UpdateClientAddr(fp, true, testAddr, "test-host"); err != nil {
		t.Fatalf("UpdateClientAddr: %v", err)
	}

	// Verify the address was updated and client is now online.
	clients = auth.ListClients(qmanage.ClientFilter{})
	if clients[fp].LastAddr != testAddr {
		t.Errorf("expected LastAddr %v, got %v", testAddr, clients[fp].LastAddr)
	}
	if !clients[fp].Online {
		t.Error("expected client to be online after UpdateClientAddr")
	}
	if clients[fp].LastSeen.IsZero() {
		t.Error("expected LastSeen to be set after UpdateClientAddr")
	}

	// Update to a new address.
	newAddr := netip.MustParseAddrPort("10.0.0.50:12345")
	if err := auth.UpdateClientAddr(fp, true, newAddr, "test-host"); err != nil {
		t.Fatalf("UpdateClientAddr: %v", err)
	}

	// Verify the address was updated again.
	clients = auth.ListClients(qmanage.ClientFilter{})
	if clients[fp].LastAddr != newAddr {
		t.Errorf("expected LastAddr %v, got %v", newAddr, clients[fp].LastAddr)
	}

	// Verify setting client offline works.
	if err := auth.UpdateClientAddr(fp, false, netip.AddrPort{}, ""); err != nil {
		t.Fatalf("UpdateClientAddr (offline): %v", err)
	}
	clients = auth.ListClients(qmanage.ClientFilter{})
	if clients[fp].Online {
		t.Error("expected client to be offline after UpdateClientAddr with online=false")
	}

	// Verify updating unknown client does NOT create a new record
	// (unauthorized clients must go through provisioning first).
	unknownFP := qdef.FP{0x99, 0x99} // non-zero FP that doesn't exist
	unknownAddr := netip.MustParseAddrPort("1.2.3.4:5678")
	err = auth.UpdateClientAddr(unknownFP, true, unknownAddr, "new-host")
	if err != nil {
		t.Errorf("UpdateClientAddr for unknown client should succeed, got %v", err)
	}
	// Verify the record was NOT created.
	clients = auth.ListClients(qmanage.ClientFilter{})
	if _, ok := clients[unknownFP]; ok {
		t.Fatal("expected unknown client record to NOT be created")
	}
}

func TestServerAddressTracking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup server auth manager.
	serverDir := t.TempDir()
	authCfg := qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         serverDir,
		ServerHostname:  "localhost",
		CleanupInterval: -1,
	}
	authMgr, err := qmanage.NewAuthManager(authCfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer authMgr.Close()

	// Setup server.
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth: authMgr,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	server.SetRoleDef("worker", qdef.RoleConfig{
		Provides: []string{"job"},
	})

	// Start server.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()

	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	addr := "localhost:" + port

	go server.Serve(ctx, packetConn)

	// Create client via CSR flow.
	clientID := qdef.Identity{Hostname: "worker-01"}
	csrPEM, keyPEM, err := qdef.CreateCSR("worker-01")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certPEM, err := authMgr.SignProvisioningCSR(csrPEM, "worker-01", []string{"worker"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	// Extract fingerprint.
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	clientID.Fingerprint = qdef.FingerprintOf(leaf)

	// Authorize client.
	authMgr.SetClientStatus(clientID.Fingerprint, qdef.StatusAuthorized)

	// Verify LastAddr is initially zero.
	clients := authMgr.ListClients(qmanage.ClientFilter{})
	if clients[clientID.Fingerprint].LastAddr.IsValid() {
		t.Errorf("expected zero LastAddr before connection, got %v", clients[clientID.Fingerprint].LastAddr)
	}

	// Connect client.
	clientStore := &mockCredentialStore{
		id:         clientID,
		certPEM:    certPEM,
		keyPEM:     keyPEM,
		rootCACert: authMgr.RootCert(),
	}

	resolver := &qmock.MockResolver{}
	resolver.SetAddress(addr)

	client := qconn.NewClient(qconn.ClientOpt{
		ServerHostname:  "localhost",
		CredentialStore: clientStore,
		Resolver:        resolver,
	})
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer client.Close()

	// Wait for client to connect.
	deadline := time.Now().Add(5 * time.Second)
	connected := false
	for time.Now().Before(deadline) {
		clients := authMgr.ListClientsInfo(true, nil)
		for _, c := range clients {
			if c.Hostname == "worker-01" && c.Online {
				connected = true
				break
			}
		}
		if connected {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !connected {
		t.Fatal("client did not connect in time")
	}

	// Give a moment for the address update to propagate.
	time.Sleep(50 * time.Millisecond)

	// Verify LastAddr was updated.
	clients = authMgr.ListClients(qmanage.ClientFilter{})
	lastAddr := clients[clientID.Fingerprint].LastAddr
	if !lastAddr.IsValid() {
		t.Fatal("expected LastAddr to be set after connection")
	}

	// Verify it's a localhost address.
	if !lastAddr.Addr().IsLoopback() {
		t.Errorf("expected loopback address, got %v", lastAddr)
	}

	t.Logf("Client connected from %v", lastAddr)
}

// --- Test Helpers ---

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
func (s *mockCredentialStore) SetRootCA(certPEM []byte) error {
	return nil // Not used in tests
}
func (s *mockCredentialStore) SaveCredentials(certPEM, keyPEM []byte) error {
	s.certPEM, s.keyPEM = certPEM, keyPEM
	// Extract fingerprint from cert.
	block, _ := pem.Decode(certPEM)
	if block != nil {
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if leaf != nil {
			s.id.Fingerprint = qdef.FingerprintOf(leaf)
		}
	}
	return nil
}
func (s *mockCredentialStore) OnUpdate() <-chan struct{} { return nil }

// TestDuplicateHostnameRejection verifies that authorizing a client with a hostname
// already used by another authorized client fails with ErrDuplicateHostname.
func TestDuplicateHostnameRejection(t *testing.T) {
	dir := t.TempDir()
	auth, err := qmanage.NewAuthManager(qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         dir,
		ServerHostname:  "localhost",
		CleanupInterval: -1, // Disable cleanup.
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create and authorize first client with hostname "shared-host".
	csr1, _, err := qdef.CreateCSR("shared-host")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert1PEM, err := auth.SignProvisioningCSR(csr1, "shared-host", []string{"role1"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block1, _ := pem.Decode(cert1PEM)
	leaf1, _ := x509.ParseCertificate(block1.Bytes)
	fp1 := qdef.FingerprintOf(leaf1)

	// Authorize first client - should succeed.
	if err := auth.SetClientStatus(fp1, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus(fp1): %v", err)
	}
	t.Logf("First client authorized: %s", fp1)

	// Create second client with same hostname "shared-host".
	csr2, _, err := qdef.CreateCSR("shared-host")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert2PEM, err := auth.SignProvisioningCSR(csr2, "shared-host", []string{"role2"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block2, _ := pem.Decode(cert2PEM)
	leaf2, _ := x509.ParseCertificate(block2.Bytes)
	fp2 := qdef.FingerprintOf(leaf2)

	// Authorize second client - should fail with duplicate hostname error.
	err = auth.SetClientStatus(fp2, qdef.StatusAuthorized)
	if err == nil {
		t.Fatal("expected ErrDuplicateHostname, got nil")
	}

	var dupErr qdef.DuplicateHostnameError
	if !errors.As(err, &dupErr) {
		t.Fatalf("expected DuplicateHostnameError, got %T: %v", err, err)
	}
	if dupErr.Hostname != "shared-host" {
		t.Errorf("expected hostname 'shared-host', got %q", dupErr.Hostname)
	}
	if dupErr.ExistingFingerprint != fp1 {
		t.Errorf("expected existing fingerprint %s, got %s", fp1, dupErr.ExistingFingerprint)
	}
	t.Logf("Second client correctly rejected: %v", err)

	// Verify second client is still unauthorized.
	status, err := auth.GetStatus(fp2)
	if err != nil {
		t.Fatalf("GetStatus(fp2): %v", err)
	}
	if status != qdef.StatusUnauthorized {
		t.Errorf("expected StatusUnauthorized, got %v", status)
	}
}

// TestDuplicateHostnameAllowedAfterRevoke verifies that a hostname becomes available
// again after the original client is revoked.
func TestDuplicateHostnameAllowedAfterRevoke(t *testing.T) {
	dir := t.TempDir()
	auth, err := qmanage.NewAuthManager(qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         dir,
		ServerHostname:  "localhost",
		CleanupInterval: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create and authorize first client.
	csr1, _, err := qdef.CreateCSR("reusable-host")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert1PEM, err := auth.SignProvisioningCSR(csr1, "reusable-host", []string{"role1"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block1, _ := pem.Decode(cert1PEM)
	leaf1, _ := x509.ParseCertificate(block1.Bytes)
	fp1 := qdef.FingerprintOf(leaf1)

	if err := auth.SetClientStatus(fp1, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus(fp1): %v", err)
	}

	// Revoke first client.
	if err := auth.SetClientStatus(fp1, qdef.StatusRevoked); err != nil {
		t.Fatalf("SetClientStatus(fp1, Revoked): %v", err)
	}
	t.Log("First client revoked")

	// Create second client with same hostname.
	csr2, _, err := qdef.CreateCSR("reusable-host")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert2PEM, err := auth.SignProvisioningCSR(csr2, "reusable-host", []string{"role2"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block2, _ := pem.Decode(cert2PEM)
	leaf2, _ := x509.ParseCertificate(block2.Bytes)
	fp2 := qdef.FingerprintOf(leaf2)

	// Authorize second client - should succeed now that first is revoked.
	if err := auth.SetClientStatus(fp2, qdef.StatusAuthorized); err != nil {
		t.Fatalf("expected success after revoke, got: %v", err)
	}
	t.Log("Second client authorized after first was revoked")
}

// TestDuplicateHostnameAllowedAfterExpiry verifies that a hostname becomes available
// again after the original client's certificate expires.
func TestDuplicateHostnameAllowedAfterExpiry(t *testing.T) {
	dir := t.TempDir()
	auth, err := qmanage.NewAuthManager(qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         dir,
		ServerHostname:  "localhost",
		CleanupInterval: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create and authorize first client.
	csr1, _, err := qdef.CreateCSR("expiry-host")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert1PEM, err := auth.SignProvisioningCSR(csr1, "expiry-host", []string{"role1"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block1, _ := pem.Decode(cert1PEM)
	leaf1, _ := x509.ParseCertificate(block1.Bytes)
	fp1 := qdef.FingerprintOf(leaf1)

	if err := auth.SetClientStatus(fp1, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus(fp1): %v", err)
	}

	// Expire the first client by setting expiry in the past.
	if err := auth.SetClientExpiry(fp1, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("SetClientExpiry: %v", err)
	}
	t.Log("First client expired")

	// Create second client with same hostname.
	csr2, _, err := qdef.CreateCSR("expiry-host")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert2PEM, err := auth.SignProvisioningCSR(csr2, "expiry-host", []string{"role2"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block2, _ := pem.Decode(cert2PEM)
	leaf2, _ := x509.ParseCertificate(block2.Bytes)
	fp2 := qdef.FingerprintOf(leaf2)

	// Authorize second client - should succeed now that first is expired.
	if err := auth.SetClientStatus(fp2, qdef.StatusAuthorized); err != nil {
		t.Fatalf("expected success after expiry, got: %v", err)
	}
	t.Log("Second client authorized after first expired")
}

// TestDuplicateHostnameDifferentHostsAllowed verifies that different hostnames
// are allowed to be authorized simultaneously.
func TestDuplicateHostnameDifferentHostsAllowed(t *testing.T) {
	dir := t.TempDir()
	auth, err := qmanage.NewAuthManager(qmanage.AuthManagerConfig{
		AppName:         "test",
		DataDir:         dir,
		ServerHostname:  "localhost",
		CleanupInterval: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer auth.Close()

	// Create and authorize first client with hostname "host-a".
	csr1, _, err := qdef.CreateCSR("host-a")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert1PEM, err := auth.SignProvisioningCSR(csr1, "host-a", []string{"role1"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block1, _ := pem.Decode(cert1PEM)
	leaf1, _ := x509.ParseCertificate(block1.Bytes)
	fp1 := qdef.FingerprintOf(leaf1)

	if err := auth.SetClientStatus(fp1, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus(fp1): %v", err)
	}

	// Create and authorize second client with hostname "host-b".
	csr2, _, err := qdef.CreateCSR("host-b")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	cert2PEM, err := auth.SignProvisioningCSR(csr2, "host-b", []string{"role2"})
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}
	block2, _ := pem.Decode(cert2PEM)
	leaf2, _ := x509.ParseCertificate(block2.Bytes)
	fp2 := qdef.FingerprintOf(leaf2)

	// Authorize second client - should succeed since hostname is different.
	if err := auth.SetClientStatus(fp2, qdef.StatusAuthorized); err != nil {
		t.Fatalf("expected success for different hostname, got: %v", err)
	}
	t.Log("Both clients authorized with different hostnames")
}
