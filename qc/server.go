package qc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

// Server implements the QUIC server logic.
type Server struct {
	addr            string
	tlsConfig       *tls.Config
	authManager     AuthorizationManager
	activeConns     sync.Map // Map of fingerprint -> *quic.Conn.
	provisioningCAs map[string]*x509.CertPool
	handler         StreamHandler
	observer        ClientObserver
	keepAlivePeriod time.Duration
}

const (
	DefaultKeepAlivePeriod = 45 * time.Second
)

var serverIdentity = Identity{
	Hostname: ":self-server:",
}

type ServerOpt struct {
	ListenOn        string
	ProvisionTokens []string

	ServerCert tls.Certificate
	CACert     *x509.Certificate

	Auth            AuthorizationManager
	Handler         StreamHandler
	Observer        ClientObserver
	KeepAlivePeriod time.Duration
}

// NewServer creates a new QUIC server.
func NewServer(opt ServerOpt) *Server {
	caPool := x509.NewCertPool()
	caPool.AddCert(opt.CACert)

	provisioningCAs := make(map[string]*x509.CertPool)
	for _, token := range opt.ProvisionTokens {
		ca, err := GenerateDerivedCA(token)
		if err == nil {
			leaf, err := x509.ParseCertificate(ca.Certificate[0])
			if err == nil {
				pool := x509.NewCertPool()
				pool.AddCert(leaf)
				provisioningCAs[token] = pool
			}
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{opt.ServerCert},
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
				if ext.Id.Equal(OIDProvisioningIdentity) {
					isProvisioning = true
					break
				}
			}

			if isProvisioning {
				for _, pool := range provisioningCAs {
					opts := x509.VerifyOptions{
						Roots:     pool,
						KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					}
					if _, err := leaf.Verify(opts); err == nil {
						return nil // Matches one of the provisioning roots.
					}
				}
				return fmt.Errorf("qconn: invalid provisioning certificate")
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
			if status == StatusRevoked {
				return fmt.Errorf("qconn: client %s is revoked or not found", leaf.Subject.CommonName)
			}
			return nil
		},
	}

	return &Server{
		addr:            opt.ListenOn,
		tlsConfig:       tlsConfig,
		authManager:     opt.Auth,
		provisioningCAs: provisioningCAs,
		handler:         opt.Handler,
		observer:        opt.Observer,
		keepAlivePeriod: opt.KeepAlivePeriod,
	}
}

func (s *Server) logf(id Identity, format string, v ...interface{}) {
	if s.observer == nil {
		return
	}
	s.observer.Logf(id, format, v...)
}

func (s *Server) notifyState(id Identity, state ClientState) {
	if s.observer == nil {
		return
	}
	s.observer.OnStateChange(id, state)
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
		conn, err := listener.Accept(ctx)
		if err != nil {
			s.logf(serverIdentity, "failed to accept connection: %v", err)
			return
		}
		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn *quic.Conn) error {
	cs := conn.ConnectionState()
	pcList := cs.TLS.PeerCertificates
	if len(pcList) == 0 {
		return fmt.Errorf("client disconnected: no peer certificates")
	}
	leaf := pcList[0]
	id := Identity{
		Hostname:    leaf.Subject.CommonName,
		Fingerprint: fmt.Sprintf("%x", Fingerprint(leaf.Raw)),
	}
	s.notifyState(id, StateConnected)
	defer s.notifyState(id, StateDisconnected)

	// Check for provisioning extension instead of hostname.
	var isProvisioning bool
	for _, cert := range pcList {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(OIDProvisioningIdentity) {
				isProvisioning = true
				break
			}
		}
		if isProvisioning {
			break
		}
	}

	if isProvisioning {
		// Identify which token matched.
		matchedToken := ""
		leaf := conn.ConnectionState().TLS.PeerCertificates[0]
		for token, pool := range s.provisioningCAs {
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := leaf.Verify(opts); err == nil {
				matchedToken = token
				break
			}
		}
		s.handleProvisioning(ctx, id, conn, matchedToken)
		return nil
	}

	// Authorization check loop.
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		status, err := s.authManager.GetStatus(leaf)
		if err != nil || status != StatusAuthorized {
			if conn.Context().Err() != nil {
				s.logf(id, "client %s disconnected while unauthorized.", id.Hostname)
				return nil
			}
			time.Sleep(1 * time.Second) // Wait for authorization.
			continue
		}
		break // Authorized.
	}

	s.notifyState(id, StateAuthorized)
	s.activeConns.Store(id.Fingerprint, conn)
	defer s.activeConns.Delete(id.Fingerprint)

	// Now that it's authorized, accept streams.
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return nil
		}
		go s.handler.Handle(ctx, stream)
	}
}

func (s *Server) handleProvisioning(ctx context.Context, id Identity, conn *quic.Conn, token string) error {
	s.logf(id, "entering provisioning circuit for token: %s", token[:min(len(token), 4)]+"...")
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to accept stream: %w", err)
	}
	defer stream.Close()

	var req Identity
	if err := cbor.NewDecoder(stream).Decode(&req); err != nil {
		return fmt.Errorf("failed to decode request: %w", err)
	}

	s.notifyState(req, StateProvisioning)

	certPEM, keyPEM, err := s.authManager.IssueClientCertificate(&req)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}

	resp := struct {
		CertPEM []byte `json:"cert_pem"`
		KeyPEM  []byte `json:"key_pem"`
	}{certPEM, keyPEM}

	if err := cbor.NewEncoder(stream).Encode(resp); err != nil {
		return fmt.Errorf("failed to encode provisioning response: %w", err)
	}
	s.notifyState(req, StateProvisioned)

	// Wait for client to close the stream before returning.
	_ = stream.Close()
	select {
	case <-ctx.Done():
	case <-stream.Context().Done():
	case <-time.After(1 * time.Second):
	}
	return nil
}
