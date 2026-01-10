package qmanage_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kardianos/qconn/anex"
	"github.com/kardianos/qconn/qclient"
	"github.com/kardianos/qconn/qconn"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmanage"
	"github.com/kardianos/qconn/qmock"
)

func TestClientStoreOperations(t *testing.T) {
	dir := t.TempDir()

	store, err := qmanage.NewClientStoreWithDir(dir)
	if err != nil {
		t.Fatalf("NewClientStoreWithDir: %v", err)
	}
	defer store.Close()

	// Test initial state.
	id, err := store.GetIdentity()
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if id.Hostname != "" {
		t.Errorf("expected empty identity, got %v", id)
	}

	// Test SetProvisionToken.
	if err := store.SetProvisionToken("test-token-123"); err != nil {
		t.Fatalf("SetProvisionToken: %v", err)
	}
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

	if err := store.SaveCredentials(testID, certPEM, keyPEM); err != nil {
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

	// Test role definitions.
	workerRole := qmanage.RoleConfig{
		Provides: []string{"job"},
		SendsTo:  []string{"status"},
	}
	if err := auth.SetRoleDef("worker", workerRole); err != nil {
		t.Fatalf("SetRoleDef: %v", err)
	}

	retrieved, ok := auth.GetRoleDef("worker")
	if !ok {
		t.Fatal("expected to find worker role")
	}
	if len(retrieved.Provides) != 1 || retrieved.Provides[0] != "job" {
		t.Errorf("unexpected role config: %+v", retrieved)
	}

	roles := auth.ListRoleDefs()
	if len(roles) != 1 {
		t.Errorf("expected 1 role, got %d", len(roles))
	}

	// Test static authorizations.
	fp := "abc123fingerprint"
	if err := auth.SetStaticAuthorization(fp, []string{"worker", "admin"}); err != nil {
		t.Fatalf("SetStaticAuthorization: %v", err)
	}

	got := auth.GetStaticAuthorization(fp)
	if len(got) != 2 {
		t.Errorf("expected 2 roles, got %d", len(got))
	}

	// Test AuthorizeRoles filtering.
	authorized := auth.AuthorizeRoles(fp, []string{"worker", "superadmin"})
	if len(authorized) != 1 || authorized[0] != "worker" {
		t.Errorf("expected only 'worker' authorized, got %v", authorized)
	}

	auths := auth.ListAuthorizations()
	if len(auths) != 1 {
		t.Errorf("expected 1 authorization, got %d", len(auths))
	}

	// Test client status.
	if err := auth.SetClientStatus(fp, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus: %v", err)
	}

	clients := auth.ListClients()
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
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client")
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
	fp := qdef.FingerprintHex(leaf)
	status, err := auth.GetStatus(leaf)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != qdef.StatusUnauthorized {
		t.Errorf("expected StatusUnauthorized, got %v", status)
	}

	clients := auth.ListClients()
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
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client")
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	// Get fingerprint.
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	oldFP := qdef.FingerprintHex(leaf)

	// Authorize the client.
	if err := auth.SetClientStatus(oldFP, qdef.StatusAuthorized); err != nil {
		t.Fatalf("SetClientStatus: %v", err)
	}
	if err := auth.SetStaticAuthorization(oldFP, []string{"worker"}); err != nil {
		t.Fatalf("SetStaticAuthorization: %v", err)
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
	newFP := qdef.FingerprintHex(newLeaf)

	if newFP == oldFP {
		t.Error("expected different fingerprint after renewal")
	}

	// Verify status was preserved.
	status, err := auth.GetStatus(newLeaf)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != qdef.StatusAuthorized {
		t.Errorf("expected StatusAuthorized after renewal, got %v", status)
	}

	// Verify authorizations were migrated.
	roles := auth.GetStaticAuthorization(newFP)
	if len(roles) != 1 || roles[0] != "worker" {
		t.Errorf("expected roles to migrate, got %v", roles)
	}

	// Verify old fingerprint was removed.
	oldRoles := auth.GetStaticAuthorization(oldFP)
	if len(oldRoles) != 0 {
		t.Errorf("expected old fingerprint to be removed, got %v", oldRoles)
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
		ServerHostname:  "localhost", // Match the address clients connect to.
		CleanupInterval: -1,          // Disable cleanup goroutine for test.
	}
	authMgr, err := qmanage.NewAuthManager(authCfg)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	defer authMgr.Close()

	// Setup Hub with role definitions.
	hub := anex.NewHub(10 * time.Second)
	hub.SetRoleDef("printer-provider", anex.RoleConfig{
		Provides: []string{"printer"},
	})
	hub.SetRoleDef("print-requester", anex.RoleConfig{
		SendsTo: []string{"printer"},
	})

	// Setup server.
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth:     authMgr,
		Handler:  hub,
		Listener: hub,
		Observer: qmock.NewTestObserver(ctx, t),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Start server.
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer packetConn.Close()

	_, port, _ := net.SplitHostPort(packetConn.LocalAddr().String())
	addr := "localhost:" + port

	go server.Serve(ctx, packetConn)

	// Create provider client using CSR flow.
	providerID := qdef.Identity{Hostname: "provider-01"}
	providerCSRPEM, providerKeyPEM, err := qdef.CreateCSR("provider-01")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	providerCertPEM, err := authMgr.SignProvisioningCSR(providerCSRPEM, "provider-01")
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
	provFpStr := providerID.Fingerprint.String()
	authMgr.SetClientStatus(provFpStr, qdef.StatusAuthorized)
	authMgr.SetStaticAuthorization(provFpStr, []string{"printer-provider"})
	hub.SetStaticAuthorization(provFpStr, []string{"printer-provider"})

	provStore := &mockCredentialStore{
		id:         providerID,
		certPEM:    providerCertPEM,
		keyPEM:     providerKeyPEM,
		rootCACert: authMgr.RootCert(),
	}

	provClient := qclient.NewClient(addr, provStore)

	type PrintReq struct{ Content string }
	type PrintResp struct{ OK bool }

	_ = qclient.Handle(provClient, "printer", qclient.StaticDevices("printer"), func(ctx context.Context, id qdef.Identity, req *PrintReq) (*PrintResp, error) {
		t.Logf("Provider received print request: %s", req.Content)
		return &PrintResp{OK: true}, nil
	})

	if err := provClient.Start(ctx); err != nil {
		t.Fatalf("Provider start: %v", err)
	}
	defer provClient.Close()

	// Wait for provider to connect and register devices.
	deadline := time.Now().Add(5 * time.Second)
	providerOnline := false
	for time.Now().Before(deadline) {
		states := hub.ListHostStates(false)
		for _, s := range states {
			if s.Identity.Hostname == "provider-01" && s.Online && len(s.Identity.Devices) > 0 {
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

	// Re-trigger state change to sync roles with hub.
	hub.OnStateChange(providerID, qdef.StateAuthorized)

	// Create requester client.
	requesterID := qdef.Identity{Hostname: "requester-01"}
	csrPEM, requesterKeyPEM, err := qdef.CreateCSR("requester-01")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	requesterCertPEM, err := authMgr.SignProvisioningCSR(csrPEM, "requester-01")
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
	reqFpStr := requesterID.Fingerprint.String()
	authMgr.SetClientStatus(reqFpStr, qdef.StatusAuthorized)
	authMgr.SetStaticAuthorization(reqFpStr, []string{"print-requester"})
	hub.SetStaticAuthorization(reqFpStr, []string{"print-requester"})

	reqStore := &mockCredentialStore{
		id:         requesterID,
		certPEM:    requesterCertPEM,
		keyPEM:     requesterKeyPEM,
		rootCACert: authMgr.RootCert(),
	}

	reqClient := qclient.NewClient(addr, reqStore)
	if err := reqClient.Start(ctx); err != nil {
		t.Fatalf("Requester start: %v", err)
	}
	defer reqClient.Close()

	// Wait for requester to connect.
	deadline = time.Now().Add(5 * time.Second)
	requesterOnline := false
	for time.Now().Before(deadline) {
		states := hub.ListHostStates(false)
		for _, s := range states {
			if s.Identity.Hostname == "requester-01" && s.Online {
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

	hub.OnStateChange(requesterID, qdef.StateAuthorized)

	// Send print request.
	target := qdef.Addr{
		Service: qdef.ServiceUser,
		Type:    "printer",
		Machine: providerID.Fingerprint.String(),
	}

	resp, err := qclient.Request[PrintReq, PrintResp](reqClient, ctx, target, &PrintReq{Content: "Hello from test"})
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
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client")
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	fp := qdef.FingerprintOf(leaf)

	auth.SetClientStatus(fp.String(), qdef.StatusAuthorized)

	// Revoke the client.
	if err := auth.Revoke(qdef.Identity{Fingerprint: fp}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Verify status.
	status, err := auth.GetStatus(leaf)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != qdef.StatusRevoked {
		t.Errorf("expected StatusRevoked, got %v", status)
	}

	// Verify renewal fails.
	newCSRPEM, _, _ := qdef.CreateCSR("test-client")
	_, err = auth.SignRenewalCSR(newCSRPEM, fp.String())
	if err != qdef.ErrClientRevoked {
		t.Errorf("expected ErrClientRevoked, got %v", err)
	}
}

func TestSignalChannel(t *testing.T) {
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
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client")
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)

	// Get signal channel.
	sig := auth.GetSignal(leaf)

	// Change status in goroutine.
	go func() {
		time.Sleep(50 * time.Millisecond)
		auth.SetClientStatus(qdef.FingerprintHex(leaf), qdef.StatusAuthorized)
	}()

	// Wait for signal.
	select {
	case <-sig:
		// Good.
	case <-time.After(1 * time.Second):
		t.Error("expected signal channel to be closed")
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

	// Add some data.
	auth1.SetRoleDef("worker", qmanage.RoleConfig{Provides: []string{"job"}})
	auth1.SetStaticAuthorization("fp123", []string{"worker"})

	csrPEM, _, _ := qdef.CreateCSR("test-client")
	auth1.SignProvisioningCSR(csrPEM, "test-client")

	caCert := auth1.RootCert()
	auth1.Close()

	// Reopen and verify data persisted.
	auth2, err := qmanage.NewAuthManager(cfg)
	if err != nil {
		t.Fatalf("NewAuthManager (reopen): %v", err)
	}
	defer auth2.Close()

	// CA should be the same.
	if qdef.FingerprintHex(auth2.RootCert()) != qdef.FingerprintHex(caCert) {
		t.Error("CA fingerprint changed after reopen")
	}

	// Role should be present.
	role, ok := auth2.GetRoleDef("worker")
	if !ok {
		t.Error("expected worker role to persist")
	}
	if len(role.Provides) != 1 || role.Provides[0] != "job" {
		t.Errorf("unexpected role config: %+v", role)
	}

	// Authorization should be present.
	roles := auth2.GetStaticAuthorization("fp123")
	if len(roles) != 1 || roles[0] != "worker" {
		t.Errorf("expected authorization to persist, got %v", roles)
	}

	// Client should be present.
	clients := auth2.ListClients()
	if len(clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(clients))
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
	var fingerprints []string
	for i := 0; i < 3; i++ {
		hostname := "client-" + string(rune('a'+i))
		csrPEM, _, err := qdef.CreateCSR(hostname)
		if err != nil {
			t.Fatalf("CreateCSR: %v", err)
		}
		certPEM, err := auth.SignProvisioningCSR(csrPEM, hostname)
		if err != nil {
			t.Fatalf("SignProvisioningCSR: %v", err)
		}

		block, _ := pem.Decode(certPEM)
		leaf, _ := x509.ParseCertificate(block.Bytes)
		fingerprints = append(fingerprints, qdef.FingerprintHex(leaf))
	}

	// Authorize all clients and give them roles.
	for _, fp := range fingerprints {
		auth.SetClientStatus(fp, qdef.StatusAuthorized)
		auth.SetStaticAuthorization(fp, []string{"worker"})
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
	clients := auth.ListClients()
	if len(clients) != 3 {
		t.Fatalf("expected 3 clients, got %d", len(clients))
	}

	// Run cleanup.
	removed := auth.CleanupExpiredClients()
	if removed != 2 {
		t.Errorf("expected 2 clients removed, got %d", removed)
	}

	// Verify only the non-expired client remains.
	clients = auth.ListClients()
	if len(clients) != 1 {
		t.Errorf("expected 1 client remaining, got %d", len(clients))
	}

	// Verify the right client remains.
	if _, ok := clients[fingerprints[2]]; !ok {
		t.Error("expected non-expired client to remain")
	}

	// Verify authorizations for expired clients were also removed.
	if roles := auth.GetStaticAuthorization(fingerprints[0]); len(roles) != 0 {
		t.Errorf("expected authorization for expired client to be removed, got %v", roles)
	}
	if roles := auth.GetStaticAuthorization(fingerprints[1]); len(roles) != 0 {
		t.Errorf("expected authorization for expired client to be removed, got %v", roles)
	}

	// Verify non-expired client's authorization remains.
	if roles := auth.GetStaticAuthorization(fingerprints[2]); len(roles) != 1 {
		t.Errorf("expected authorization for non-expired client to remain, got %v", roles)
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
	certPEM, err := auth.SignProvisioningCSR(csrPEM, "test-client")
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	fp := qdef.FingerprintHex(leaf)

	// Initially LastAddr should be zero value.
	clients := auth.ListClients()
	if clients[fp].LastAddr.IsValid() {
		t.Errorf("expected zero LastAddr, got %v", clients[fp].LastAddr)
	}

	// Update the address.
	testAddr := netip.MustParseAddrPort("192.168.1.100:54321")
	if err := auth.UpdateClientAddr(fp, testAddr); err != nil {
		t.Fatalf("UpdateClientAddr: %v", err)
	}

	// Verify the address was updated.
	clients = auth.ListClients()
	if clients[fp].LastAddr != testAddr {
		t.Errorf("expected LastAddr %v, got %v", testAddr, clients[fp].LastAddr)
	}

	// Update to a new address.
	newAddr := netip.MustParseAddrPort("10.0.0.50:12345")
	if err := auth.UpdateClientAddr(fp, newAddr); err != nil {
		t.Fatalf("UpdateClientAddr: %v", err)
	}

	// Verify the address was updated again.
	clients = auth.ListClients()
	if clients[fp].LastAddr != newAddr {
		t.Errorf("expected LastAddr %v, got %v", newAddr, clients[fp].LastAddr)
	}

	// Verify updating unknown client returns error.
	err = auth.UpdateClientAddr("unknown-fingerprint", netip.MustParseAddrPort("1.2.3.4:5678"))
	if err != qdef.ErrUnknownClient {
		t.Errorf("expected ErrUnknownClient, got %v", err)
	}
}

func TestHubAddressTracking(t *testing.T) {
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

	// Setup Hub with address updater.
	hub := anex.NewHub(10 * time.Second)
	hub.SetAddressUpdater(authMgr)
	hub.SetRoleDef("worker", anex.RoleConfig{
		Provides: []string{"job"},
	})

	// Setup server.
	server, err := qconn.NewServer(qconn.ServerOpt{
		Auth:     authMgr,
		Handler:  hub,
		Listener: hub,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

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
	certPEM, err := authMgr.SignProvisioningCSR(csrPEM, "worker-01")
	if err != nil {
		t.Fatalf("SignProvisioningCSR: %v", err)
	}

	// Extract fingerprint.
	block, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	clientID.Fingerprint = qdef.FingerprintOf(leaf)
	clientFpStr := clientID.Fingerprint.String()

	// Authorize client.
	authMgr.SetClientStatus(clientFpStr, qdef.StatusAuthorized)
	authMgr.SetStaticAuthorization(clientFpStr, []string{"worker"})
	hub.SetStaticAuthorization(clientFpStr, []string{"worker"})

	// Verify LastAddr is initially zero.
	clients := authMgr.ListClients()
	if clients[clientFpStr].LastAddr.IsValid() {
		t.Errorf("expected zero LastAddr before connection, got %v", clients[clientFpStr].LastAddr)
	}

	// Connect client.
	clientStore := &mockCredentialStore{
		id:         clientID,
		certPEM:    certPEM,
		keyPEM:     keyPEM,
		rootCACert: authMgr.RootCert(),
	}

	client := qclient.NewClient(addr, clientStore)
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Client start: %v", err)
	}
	defer client.Close()

	// Wait for client to connect.
	deadline := time.Now().Add(5 * time.Second)
	connected := false
	for time.Now().Before(deadline) {
		states := hub.ListHostStates(false)
		for _, s := range states {
			if s.Identity.Hostname == "worker-01" && s.Online {
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
	clients = authMgr.ListClients()
	lastAddr := clients[clientFpStr].LastAddr
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
func (s *mockCredentialStore) SaveCredentials(id qdef.Identity, certPEM, keyPEM []byte) error {
	s.id, s.certPEM, s.keyPEM = id, certPEM, keyPEM
	return nil
}
func (s *mockCredentialStore) OnUpdate() <-chan struct{} { return nil }
