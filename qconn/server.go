package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"github.com/kardianos/qconn/qstate"
	"github.com/quic-go/quic-go"
)

var serverConnTransitions = []qstate.Transition[qdef.ServerConnState]{
	// From New
	{From: qdef.ConnNew, To: qdef.ConnProvisioning, Name: "is_provisioning_cert"},
	{From: qdef.ConnNew, To: qdef.ConnPendingAuth, Name: "is_normal_cert"},
	{From: qdef.ConnNew, To: qdef.ConnDisconnected, Name: "immediate_disconnect"},

	// From Provisioning
	{From: qdef.ConnProvisioning, To: qdef.ConnDisconnected, Name: "provisioning_done"},

	// From PendingAuth
	{From: qdef.ConnPendingAuth, To: qdef.ConnAuthorized, Name: "auth_approved"},
	{From: qdef.ConnPendingAuth, To: qdef.ConnDisconnected, Name: "auth_denied_or_lost"},

	// From Authorized
	{From: qdef.ConnAuthorized, To: qdef.ConnDisconnected, Name: "connection_lost"},
}

// newServerConnMachine creates a state machine for server-side connection tracking.
func newServerConnMachine(on func(from, to qdef.ServerConnState, name string)) *qstate.Machine[qdef.ServerConnState] {
	return qstate.New(
		qdef.ConnNew,
		serverConnTransitions,
		on,
	)
}

// serverConnStateToClientState converts qdef.ServerConnState to qdef.ClientState for observer notifications.
func serverConnStateToClientState(s qdef.ServerConnState) qdef.ClientState {
	switch s {
	case qdef.ConnNew:
		return qdef.StateConnected // New connection is effectively "connected"
	case qdef.ConnProvisioning:
		return qdef.StateProvisioning
	case qdef.ConnPendingAuth:
		return qdef.StateConnected // Pending auth is still "connected" from observer perspective
	case qdef.ConnAuthorized:
		return qdef.StateAuthorized
	case qdef.ConnDisconnected:
		return qdef.StateDisconnected
	default:
		return qdef.StateDisconnected
	}
}

// Server implements the QUIC server logic.
type Server struct {
	addr                string
	tlsConfig           *tls.Config
	authManager         qdef.AuthorizationManager
	provisioningPool    *x509.CertPool
	handler             qdef.StreamHandler
	observer            qdef.ClientObserver
	listener            qdef.StateListener
	keepAlivePeriod     time.Duration
	renewalLimiter      *rateLimiter
	provisioningLimiter *rateLimiter
	Router              qdef.StreamRouter
	cancel              context.CancelFunc // Cancels background goroutines like rate limiter cleanup
}

const (
	DefaultKeepAlivePeriod      = 45 * time.Second
	DefaultRenewalInterval      = 1 * time.Hour
	DefaultProvisioningInterval = 1 * time.Minute
)

var serverIdentity = qdef.Identity{
	Hostname: ":self-server:",
}

type ServerOpt struct {
	// ListenOn is the UDP address to listen on (e.g., ":4433").
	ListenOn string

	// ProvisionTokens is a list of shared secrets used to authorize new clients
	// during the provisioning phase.
	ProvisionTokens []string

	// Auth is the AuthorizationManager responsible for verifying client identities,
	// managing revocation, and issuing/renewing client certificates.
	// It also provides the root CA certificate used for verifying client certificates.
	Auth qdef.AuthorizationManager

	// Handler is the default stream handler for incoming client requests.
	Handler qdef.StreamHandler

	// Observer receives lifecycle events and logs from the server.
	Observer qdef.ClientObserver

	// Listener is notified of client connection/disconnection events.
	Listener qdef.StateListener

	// KeepAlivePeriod specifies how often to send QUIC keep-alive frames.
	KeepAlivePeriod time.Duration

	// RenewalInterval is the minimum time between certificate renewals for a client.
	// If zero, defaults to DefaultRenewalInterval.
	RenewalInterval time.Duration

	// ProvisioningInterval is the minimum time between provisioning attempts from the same IP.
	// If zero, defaults to DefaultProvisioningInterval.
	ProvisioningInterval time.Duration
}

// NewServer creates a new QUIC server.
func NewServer(opt ServerOpt) (*Server, error) {
	if opt.Auth == nil {
		return nil, fmt.Errorf("qconn: auth is required")
	}
	cert, err := opt.Auth.ServerCertificate()
	if err != nil {
		return nil, fmt.Errorf("qconn: failed to get server certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(opt.Auth.RootCert())

	provisioningPool := x509.NewCertPool()
	for _, token := range opt.ProvisionTokens {
		ca, err := qdef.GenerateDerivedCA(token)
		if err == nil {
			leaf, err := x509.ParseCertificate(ca.Certificate[0])
			if err == nil {
				provisioningPool.AddCert(leaf)
			}
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("qconn: no client certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("qconn: failed to parse client cert: %w", err)
			}

			// Check if it's a provisioning certificate.
			var isProvisioning bool
			for _, ext := range leaf.Extensions {
				if ext.Id.Equal(qdef.OIDProvisioningIdentity) {
					isProvisioning = true
					break
				}
			}

			if isProvisioning {
				opts := x509.VerifyOptions{
					Roots:     provisioningPool,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}
				if _, err := leaf.Verify(opts); err != nil {
					return fmt.Errorf("qconn: invalid provisioning certificate: %w", err)
				}
				return nil
			}

			// Normal certificate validation.
			opts := x509.VerifyOptions{
				Roots:     caPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := leaf.Verify(opts); err != nil {
				return fmt.Errorf("qconn: failed to verify client certificate: %w", err)
			}

			status, err := opt.Auth.GetStatus(leaf)
			fp := qdef.FingerprintHex(leaf)
			if err != nil {
				return fmt.Errorf("qconn: failed to get auth status for %s [%s]: %w", leaf.Subject.CommonName, fp, err)
			}
			if status == qdef.StatusRevoked {
				return fmt.Errorf("qconn: client %s [%s] is revoked or not found", leaf.Subject.CommonName, fp)
			}
			return nil
		},
	}

	renewalInterval := opt.RenewalInterval
	if renewalInterval <= 0 {
		renewalInterval = DefaultRenewalInterval
	}

	provisioningInterval := opt.ProvisioningInterval
	if provisioningInterval <= 0 {
		provisioningInterval = DefaultProvisioningInterval
	}

	// Create a context for background goroutines (rate limiter cleanup).
	bgCtx, cancel := context.WithCancel(context.Background())

	s := &Server{
		addr:                opt.ListenOn,
		tlsConfig:           tlsConfig,
		authManager:         opt.Auth,
		provisioningPool:    provisioningPool,
		handler:             opt.Handler,
		observer:            opt.Observer,
		listener:            opt.Listener,
		keepAlivePeriod:     opt.KeepAlivePeriod,
		renewalLimiter:      newRateLimiter(bgCtx, renewalInterval),
		provisioningLimiter: newRateLimiter(bgCtx, provisioningInterval),
		cancel:              cancel,
	}

	qdef.Handle(&s.Router, qdef.ServiceProvision, "", s.handleProvisioning)
	qdef.Handle(&s.Router, qdef.ServiceSystem, "renew", s.handleRenewal)

	if s.handler != nil {
		s.handler.RegisterHandlers(&s.Router)
	}

	return s, nil
}

func (s *Server) logf(id qdef.Identity, format string, v ...interface{}) {
	if s.observer == nil {
		return
	}
	s.observer.Logf(id, format, v...)
}

func (s *Server) notifyState(id qdef.Identity, state qdef.ClientState) {
	if s.observer != nil {
		s.observer.OnStateChange(id, state)
	}
	if s.listener != nil {
		s.listener.OnStateChange(id, state)
	}
}

// Serve starts the server using pre-configured listeners. This is ideal for testing.
func (s *Server) Serve(ctx context.Context, packetConn net.PacketConn) error {
	kap := s.keepAlivePeriod
	if kap == 0 {
		kap = DefaultKeepAlivePeriod
	}
	qc := &quic.Config{
		KeepAlivePeriod: kap,
		MaxIdleTimeout:  kap * 4,
	}
	listener, err := quic.Listen(packetConn, s.tlsConfig, qc)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener from PacketConn: %w", err)
	}

	go s.acceptLoop(ctx, listener)

	return nil
}

// ListenAndServe starts the QUIC server.
func (s *Server) ListenAndServe(ctx context.Context) error {
	packetConn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP packet conn: %w", err)
	}

	s.addr = packetConn.LocalAddr().String()
	s.logf(serverIdentity, "QUIC server listening on %s", s.addr)

	return s.Serve(ctx, packetConn)
}

// Close stops background goroutines like rate limiter cleanup.
// Call this when the server is shutting down.
func (s *Server) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

// acceptLoop correctly takes the *quic.Listener struct pointer.
func (s *Server) acceptLoop(ctx context.Context, listener *quic.Listener) {
	defer func() { _ = listener.Close() }()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := listener.Accept(ctx)
		if err != nil {
			s.logf(serverIdentity, "failed to accept connection: %v", err)
			return
		}
		go func() { _ = s.handleConnection(ctx, conn) }()
	}
}

func (s *Server) handleConnection(ctx context.Context, conn *quic.Conn) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logf(serverIdentity, "panic in handleConnection: %v", r)
			err = fmt.Errorf("internal server error")
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cs := conn.ConnectionState()
	pcList := cs.TLS.PeerCertificates
	if len(pcList) == 0 {
		return fmt.Errorf("client disconnected: no peer certificates")
	}
	leaf := pcList[0]

	remoteAddr := conn.RemoteAddr().String()
	id := qdef.Identity{
		Hostname:    leaf.Subject.CommonName,
		Address:     remoteAddr,
		Fingerprint: qdef.FingerprintHex(leaf),
		// Roles are managed server-side, not extracted from certificate.
	}

	// Create per-connection state machine.
	connState := newServerConnMachine(func(from, to qdef.ServerConnState, name string) {
		s.notifyState(id, serverConnStateToClientState(to))
	})

	// Check for provisioning extension instead of hostname.
	var isProvisioning bool
	for _, cert := range pcList {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(qdef.OIDProvisioningIdentity) {
				isProvisioning = true
				break
			}
		}
		if isProvisioning {
			break
		}
	}

	// Track whether we notified the listener so we can clean up properly.
	var notifiedConnect bool
	defer func() {
		if err := connState.TransitionTo(qdef.ConnDisconnected); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}
		if notifiedConnect && s.listener != nil {
			s.listener.OnIdentityDisconnect(id)
		}
	}()

	if isProvisioning {
		// Transition: New -> Provisioning
		if err := connState.TransitionTo(qdef.ConnProvisioning); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}
	} else {
		// Transition: New -> PendingAuth
		if err := connState.TransitionTo(qdef.ConnPendingAuth); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}

		// Authorization check loop - wait until client is authorized.
		for {
			status, err := s.authManager.GetStatus(leaf)
			if err != nil || status != qdef.StatusAuthorized {
				sig := s.authManager.GetSignal(leaf)
				select {
				case <-ctx.Done():
					return nil
				case <-conn.Context().Done():
					return nil
				case <-sig:
					continue
				}
			}
			break // Authorized.
		}

		// Transition: PendingAuth -> Authorized
		if err := connState.TransitionTo(qdef.ConnAuthorized); err != nil {
			s.logf(id, "qconn: state transition error: %v", err)
		}

		// Only notify listener AFTER authorization is complete.
		// This prevents the hub from routing to unauthorized clients.
		if s.listener != nil {
			s.listener.OnIdentityConnect(id, conn)
			notifiedConnect = true
		}
	}

	// Now that it's authorized (or provisioning), accept streams.
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-conn.Context().Done():
			return nil
		default:
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil
		}
		go s.handleStream(ctx, id, conn, stream, isProvisioning)
	}
}

func (s *Server) handleStream(ctx context.Context, id qdef.Identity, conn *quic.Conn, stream qdef.Stream, provisioningCert bool) {
	defer func() {
		if r := recover(); r != nil {
			s.logf(id, "panic in handleStream: %v", r)
			_ = stream.Close()
		}
	}()

	dec := cbor.NewDecoder(stream)
	var msg qdef.Message
	if err := dec.Decode(&msg); err != nil {
		if err != io.EOF {
			s.logf(id, "failed to decode message: %v", err)
		}
		h := s.handler
		if h != nil {
			h.Handle(ctx, id, qdef.Message{}, stream)
		}
		return
	}

	if provisioningCert {
		msg.Target.Service = qdef.ServiceProvision
	}

	if s.Router.Dispatch(ctx, id, msg, stream) {
		return
	}

	h := s.handler
	if h != nil {
		h.Handle(ctx, id, msg, stream)
	}
}

func (s *Server) handleRenewal(ctx context.Context, id qdef.Identity, req *qdef.RenewalRequest) (*qdef.CredentialResponse, error) {
	// Rate limit: atomically check and record to prevent race conditions.
	if allowed, remaining := s.renewalLimiter.allow(id.Fingerprint); !allowed {
		return nil, fmt.Errorf("%w: renewal for %s: wait %v", qdef.ErrRateLimited, id.Hostname, remaining)
	}

	certPEM, err := s.authManager.SignRenewalCSR(req.CSRPEM, id.Fingerprint)
	if err != nil {
		return nil, err
	}

	return &qdef.CredentialResponse{CertPEM: certPEM}, nil
}

func (s *Server) handleProvisioning(ctx context.Context, id qdef.Identity, req *qdef.ProvisioningRequest) (*qdef.CredentialResponse, error) {
	// Rate limit by IP address (provisioning clients don't have fingerprints yet).
	clientIP, _, _ := net.SplitHostPort(id.Address)
	if clientIP == "" {
		clientIP = id.Address // Fallback if no port in address
	}
	// Reject requests with empty/invalid addresses to prevent rate limit bypass.
	if clientIP == "" {
		return nil, fmt.Errorf("invalid client address for rate limiting")
	}

	// Atomically check and record to prevent race conditions.
	if allowed, remaining := s.provisioningLimiter.allow(clientIP); !allowed {
		return nil, fmt.Errorf("%w: provisioning from %s: wait %v", qdef.ErrRateLimited, clientIP, remaining)
	}

	provId := qdef.Identity{Hostname: req.Hostname}
	s.notifyState(provId, qdef.StateProvisioning)

	certPEM, err := s.authManager.SignProvisioningCSR(req.CSRPEM, req.Hostname)
	if err != nil {
		return nil, err
	}

	s.notifyState(provId, qdef.StateProvisioned)

	return &qdef.CredentialResponse{CertPEM: certPEM}, nil
}
