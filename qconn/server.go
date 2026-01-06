package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"github.com/quic-go/quic-go"
)

// Server implements the QUIC server logic.
type Server struct {
	addr             string
	tlsConfig        *tls.Config
	authManager      qdef.AuthorizationManager
	provisioningPool *x509.CertPool
	handler          qdef.StreamHandler
	observer         qdef.ClientObserver
	listener         qdef.StateListener
	keepAlivePeriod  time.Duration
	Router           qdef.StreamRouter
}

const (
	DefaultKeepAlivePeriod = 45 * time.Second
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
}

// NewServer creates a new QUIC server.
func NewServer(opt ServerOpt) *Server {
	cert, err := opt.Auth.ServerCertificate()
	if err != nil {
		panic(fmt.Sprintf("qconn: failed to get server certificate: %v", err))
	}
	if opt.Auth == nil {
		panic("qconn: auth is required")
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
			if err != nil {
				return fmt.Errorf("qconn: failed to get auth status for %s: %w", leaf.Subject.CommonName, err)
			}
			if status == qdef.StatusRevoked {
				return fmt.Errorf("qconn: client %s is revoked or not found", leaf.Subject.CommonName)
			}
			return nil
		},
	}

	s := &Server{
		addr:             opt.ListenOn,
		tlsConfig:        tlsConfig,
		authManager:      opt.Auth,
		provisioningPool: provisioningPool,
		handler:          opt.Handler,
		observer:         opt.Observer,
		listener:         opt.Listener,
		keepAlivePeriod:  opt.KeepAlivePeriod,
	}

	qdef.Handle(&s.Router, qdef.ServiceProvision, "", s.handleProvisioning)
	qdef.Handle(&s.Router, qdef.ServiceSystem, "renew", s.handleRenewal)

	if s.handler != nil {
		s.handler.RegisterHandlers(&s.Router)
	}

	return s
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

// acceptLoop correctly takes the *quic.Listener struct pointer.
func (s *Server) acceptLoop(ctx context.Context, listener *quic.Listener) {
	defer listener.Close()
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
		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn *quic.Conn) error {
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
		Fingerprint: fmt.Sprintf("%x", qdef.Fingerprint(leaf.Raw)),
		Roles:       qdef.ExtractRolesFromCert(leaf),
	}

	s.notifyState(id, qdef.StateConnected)
	if s.listener != nil {
		s.listener.OnIdentityConnect(id, conn)
	}

	defer func() {
		s.notifyState(id, qdef.StateDisconnected)
		if s.listener != nil {
			s.listener.OnIdentityDisconnect(id)
		}
	}()

	// Check for provisioning extension instead of hostname.
	var isProvisioning bool
pcLoop:
	for _, cert := range pcList {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(qdef.OIDProvisioningIdentity) {
				isProvisioning = true
				break pcLoop
			}
		}
	}

	if !isProvisioning {
		// Authorization check loop.
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

		s.notifyState(id, qdef.StateAuthorized)
	}

	// Now that it's authorized, accept streams.
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
	dec := cbor.NewDecoder(stream)
	var msg qdef.Message
	if err := dec.Decode(&msg); err != nil {
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

func (s *Server) handleRenewal(ctx context.Context, id qdef.Identity, _ *struct{}) (*qdef.CredentialResponse, error) {
	certPEM, keyPEM, err := s.authManager.RenewClientCertificate(&id)
	if err != nil {
		return nil, err
	}

	return &qdef.CredentialResponse{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func (s *Server) handleProvisioning(ctx context.Context, id qdef.Identity, req *qdef.Identity) (*qdef.CredentialResponse, error) {
	// Filter roles based on what's allowed.
	req.Roles = s.authManager.AuthorizeRoles(req.Fingerprint, req.Hostname, req.Roles)

	certPEM, keyPEM, err := s.authManager.IssueClientCertificate(req)
	if err != nil {
		return nil, err
	}

	return &qdef.CredentialResponse{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}
