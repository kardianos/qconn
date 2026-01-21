package qconn

import (
	"crypto/tls"
	"crypto/x509"
)

// BuildTLSConfig creates a TLS configuration for the server using the AuthManager.
// The AuthManager handles all certificate operations including:
// - Server certificate selection based on SNI (for provisioning vs normal connections)
// - Client certificate verification (against appropriate CA pools)
func BuildTLSConfig(auth AuthManager) *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return auth.ServerCertificate(hello.ServerName)
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return auth.VerifyClientCertificate(rawCerts)
		},
		NextProtos: []string{"qconn"},
	}
}

// isProvisioningCert checks if certificate is a provisioning certificate.
// Uses both OID check and legacy CommonName check for compatibility.
func isProvisioningCert(cert *x509.Certificate) bool {
	// Check for provisioning OID extension.
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDProvisioningIdentity) {
			return true
		}
	}
	// Legacy check for test certificates.
	return cert.Subject.CommonName == "provision"
}
