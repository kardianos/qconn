package qconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/kardianos/qconn/qdef"
)

// CredentialStore handles the persistence of client credentials.
type CredentialStore interface {
	GetIdentity() (qdef.Identity, error)
	GetClientCertificate() (tls.Certificate, error)
	GetRootCAs() (*x509.CertPool, error)
	SaveCredentials(id qdef.Identity, certPEM, keyPEM []byte) error
	ProvisionToken() string
	OnUpdate() <-chan struct{}
}

// Resolver handles hostname to address resolution.
type Resolver interface {
	Resolve(ctx context.Context, hostname string) (net.Addr, error)
	OnUpdate(hostname string) <-chan struct{}
}

// NetResolver is a default implementation of Resolver using standard net package.
type NetResolver struct{}

func (r NetResolver) Resolve(ctx context.Context, hostname string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", hostname)
}

func (r NetResolver) OnUpdate(hostname string) <-chan struct{} {
	return nil
}
