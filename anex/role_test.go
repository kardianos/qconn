package anex

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kardianos/qconn/qclient"
	"github.com/kardianos/qconn/qconn"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qmock"
)

func TestRoleBasedRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	hub := NewHub(1 * time.Second)
	hub.SetRoleDef("worker", RoleConfig{
		Provides: []string{"compute"},
	})
	hub.SetRoleDef("manager", RoleConfig{
		SendsTo: []string{"compute"},
	})

	auth := qmock.NewInMemoryAuthorizationManager()
	server := qconn.NewServer(qconn.ServerOpt{
		Auth:            auth,
		Handler:         hub,
		Listener:        hub,
		ProvisionTokens: []string{"secret"},
		Observer:        qmock.NewTestObserver(ctx, t),
	})
	hub.RegisterHandlers(&server.Router)

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := packetConn.LocalAddr().String()
	_, port, _ := net.SplitHostPort(addr)
	serverHostname := "localhost:" + port

	go server.Serve(ctx, packetConn)

	// Resolver for localhost.
	res := &mockResolver{addr: addr}

	// 1. Setup Worker
	workerStore := &mockCredentialStore{
		id:         qdef.Identity{Hostname: "worker-01", Roles: []string{"worker"}},
		token:      "secret",
		rootCACert: auth.RootCert(),
	}
	workerClient := qclient.NewClient(serverHostname, workerStore)
	workerClient.SetResolver(res)
	workerClient.SetObserver(qmock.NewTestObserver(ctx, t))

	type ComputeReq struct{ Job string }
	type ComputeResp struct{ Result string }
	qclient.Handle(workerClient, "compute", qclient.StaticDevices("compute"), func(ctx context.Context, id qdef.Identity, req *ComputeReq) (*ComputeResp, error) {
		return &ComputeResp{Result: "done: " + req.Job}, nil
	})

	// 2. Setup Manager
	managerStore := &mockCredentialStore{
		id:         qdef.Identity{Hostname: "manager-01", Roles: []string{"manager"}},
		token:      "secret",
		rootCACert: auth.RootCert(),
	}
	managerClient := qclient.NewClient(serverHostname, managerStore)
	managerClient.SetResolver(res)
	managerClient.SetObserver(qmock.NewTestObserver(ctx, t))

	// Pre-authorize by hostname.
	hub.SetStaticAuthorization("worker-01", []string{"worker"})
	hub.SetStaticAuthorization("manager-01", []string{"manager"})
	auth.AuthorizeAll()

	if err := workerClient.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer workerClient.Close()

	if err := managerClient.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer managerClient.Close()

	// Wait for connection and appear online in hub.
	var workerFingerprint string
	var managerFingerprint string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		states := hub.ListHostStates()
		for _, s := range states {
			if s.Identity.Hostname == "worker-01" && s.Online && len(s.Identity.Devices) > 0 {
				workerFingerprint = s.Identity.Fingerprint
			}
			if s.Identity.Hostname == "manager-01" && s.Online {
				managerFingerprint = s.Identity.Fingerprint
			}
		}
		if workerFingerprint != "" && managerFingerprint != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if workerFingerprint == "" || managerFingerprint == "" {
		t.Fatalf("clients did not connect in time (worker: %v, manager: %v)", workerFingerprint != "", managerFingerprint != "")
	}

	// Wait a bit more for the connections to be fully usable.
	time.Sleep(1 * time.Second)

	// 3. Test Routing: Manager sends 'compute' to Worker
	t.Run("AuthorizedCommunication", func(t *testing.T) {
		target := qdef.Addr{
			Machine: workerFingerprint,
			Type:    "compute",
			Service: qdef.ServiceUser,
		}

		req := ComputeReq{Job: "do work"}
		resp, err := qclient.Request[ComputeReq, ComputeResp](managerClient, ctx, target, &req)
		if err != nil {
			t.Errorf("expected authorized and successful response, got: %v", err)
		} else if resp.Result != "done: do work" {
			t.Errorf("unexpected response: %s", resp.Result)
		}
	})

	t.Run("SenderUnauthorized", func(t *testing.T) {
		// Revoke 'manager' role's ability to send 'compute'
		hub.SetRoleDef("manager", RoleConfig{
			SendsTo: []string{"nothing"},
		})

		target := qdef.Addr{
			Machine: workerFingerprint,
			Type:    "compute",
			Service: qdef.ServiceUser,
		}

		req := ComputeReq{Job: "do work"}
		_, err := qclient.Request[ComputeReq, ComputeResp](managerClient, ctx, target, &req)
		if err == nil {
			t.Error("expected unauthorized error, got nil")
		} else if err.Error() != "role [manager] not authorized to send job type \"compute\"" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ReceiverUnauthorized", func(t *testing.T) {
		// Restore manager role
		hub.SetRoleDef("manager", RoleConfig{
			SendsTo: []string{"compute"},
		})
		// Revoke worker role's ability to provide 'compute'
		hub.SetRoleDef("worker", RoleConfig{
			Provides: []string{"nothing"},
		})

		target := qdef.Addr{
			Machine: workerFingerprint,
			Type:    "compute",
			Service: qdef.ServiceUser,
		}

		req := ComputeReq{Job: "do work"}
		_, err := qclient.Request[ComputeReq, ComputeResp](managerClient, ctx, target, &req)
		if err == nil {
			t.Error("expected unauthorized error, got nil")
		} else if err.Error() != "target \""+workerFingerprint+"\" not authorized to provide job type \"compute\"" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
