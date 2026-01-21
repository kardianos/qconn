package qconn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// OIDProvisioningIdentity is a custom extension to identify provisioning certificates.
var OIDProvisioningIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// ErrDecodeCSR is returned when a CSR PEM block cannot be decoded.
var ErrDecodeCSR = errors.New("qconn: failed to decode CSR PEM")

// CSRHostnameMismatchError is returned when a CSR's CommonName doesn't match the expected hostname.
type CSRHostnameMismatchError struct {
	Got      string
	Expected string
}

func (e CSRHostnameMismatchError) Error() string {
	return fmt.Sprintf("qconn: CSR CommonName %q does not match expected hostname %q", e.Got, e.Expected)
}

// CSRUnauthorizedDNSError is returned when a CSR contains a DNS name that doesn't match the expected hostname.
type CSRUnauthorizedDNSError struct {
	Got      string
	Expected string
}

func (e CSRUnauthorizedDNSError) Error() string {
	return fmt.Sprintf("qconn: CSR contains unauthorized DNS name %q (expected %q)", e.Got, e.Expected)
}

// ProvisioningServerName returns a deterministic server name derived from the provision token.
// Both client and server use this to establish a shared TLS server name for provisioning.
func ProvisioningServerName(token string) string {
	fp := FingerprintHash([]byte("qconn-provision-sni:" + token))
	return "provision-" + fp.String()
}

// EncodeCertPEM converts an x509 certificate to PEM format.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// CreateCSR generates a new private key and certificate signing request.
// The private key stays with the client; only the CSR is sent to the server.
func CreateCSR(hostname string) (csrPEM []byte, keyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, nil, err
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return csrPEM, keyPEM, nil
}

// randomSerialNumber generates a cryptographically random serial number for certificates.
// Serial numbers should be unique and unpredictable per RFC 5280.
func randomSerialNumber() (*big.Int, error) {
	// Use 128 bits of randomness (16 bytes) for the serial number.
	// This provides sufficient uniqueness and unpredictability.
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random serial: %w", err)
	}
	// Ensure the serial number is positive by clearing the high bit.
	serialBytes[0] &= 0x7F
	return new(big.Int).SetBytes(serialBytes), nil
}

// CreateCA creates a new self-signed Certificate Authority.
// Uses timeNow() for certificate validity periods to enable testing with fake time.
func CreateCA() (caCert *x509.Certificate, caKey *ecdsa.PrivateKey, err error) {
	caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	now := timeNow()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "qconn Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, err = x509.ParseCertificate(caBytes)
	return caCert, caKey, err
}

// CreateCert creates a new certificate signed by the provided CA.
// It includes the hostname in the Subject Alternative Name (SAN) field for modern TLS validation.
// Uses timeNow() for certificate validity periods to enable testing with fake time.
func CreateCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hostname string, isServer bool) (certPEM []byte, keyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	now := timeNow()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname}, // Use SAN for modern validation.
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	if isServer {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

// GenerateDerivedCA creates a deterministic CA certificate and key based on a shared secret.
// Uses timeNow() for certificate validity periods to enable testing with fake time.
func GenerateDerivedCA(sharedSecret string) (tls.Certificate, error) {
	seed := sha256.Sum256([]byte(sharedSecret))

	// Deriving the private key directly from the seed ensures 100% determinism
	// without relying on the behavior of ecdsa.GenerateKey with a custom reader.
	params := elliptic.P256().Params()
	d := new(big.Int).SetBytes(seed[:])
	for d.Sign() == 0 || d.Cmp(params.N) >= 0 {
		seed = sha256.Sum256(seed[:])
		d.SetBytes(seed[:])
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
		D: d,
	}
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(d.Bytes())

	now := timeNow()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "qconn Provisioning CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(3, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Use rand.Reader for the signature. The signature is non-deterministic but always valid.
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// GenerateProvisioningServerCert creates a server certificate signed by the derived CA.
// Uses timeNow() for certificate validity periods to enable testing with fake time.
func GenerateProvisioningServerCert(ca tls.Certificate, hostname string) (tls.Certificate, time.Time, error) {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	caKey := ca.PrivateKey.(*ecdsa.PrivateKey)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	now := timeNow()
	expiresAt := now.Add(24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     expiresAt, // Short-lived for provisioning
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privKey,
	}, expiresAt, nil
}

// GenerateProvisioningIdentity creates a fresh leaf certificate signed by the derived CA.
// Uses timeNow() for certificate validity periods to enable testing with fake time.
func GenerateProvisioningIdentity(ca tls.Certificate) (tls.Certificate, error) {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	caKey := ca.PrivateKey.(*ecdsa.PrivateKey)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return tls.Certificate{}, err
	}

	now := timeNow()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "provision"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDProvisioningIdentity,
				Critical: false,
				Value:    []byte("provisioning"),
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	leafCert := tls.Certificate{
		Certificate: [][]byte{certBytes}, // Do not include CA in chain; server has it in pool.
		PrivateKey:  privKey,
	}

	return leafCert, nil
}

// SignCSR signs a CSR with the CA and returns the certificate.
// Uses timeNow() for certificate validity periods to enable testing with fake time.
func SignCSR(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, csrPEM []byte, expectedHostname string, isServer bool) (certPEM []byte, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, ErrDecodeCSR
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("qconn: failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("qconn: CSR signature invalid: %w", err)
	}

	// Validate that CSR matches expected hostname to prevent identity spoofing.
	if expectedHostname != "" {
		if csr.Subject.CommonName != expectedHostname {
			return nil, CSRHostnameMismatchError{Got: csr.Subject.CommonName, Expected: expectedHostname}
		}
		// Validate DNSNames only contain the expected hostname.
		for _, dns := range csr.DNSNames {
			if dns != expectedHostname {
				return nil, CSRUnauthorizedDNSError{Got: dns, Expected: expectedHostname}
			}
		}
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	now := timeNow()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(45 * 24 * time.Hour), // 45 days default validity
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if isServer {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
}
