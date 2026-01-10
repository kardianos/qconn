package qdef

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

var (
	// OIDProvisioningIdentity is a custom extension to identify provisioning certificates.
	OIDProvisioningIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
)

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

// FP is a certificate fingerprint (SHA-256 hash of the certificate's raw bytes).
type FP [32]byte

// String returns the hex-encoded fingerprint.
func (f FP) String() string {
	return hex.EncodeToString(f[:])
}

// IsZero returns true if the fingerprint is all zeros (unset).
func (f FP) IsZero() bool {
	return f == FP{}
}

// MarshalBinary implements encoding.BinaryMarshaler for efficient CBOR encoding.
func (f FP) MarshalBinary() ([]byte, error) {
	return f[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for CBOR decoding.
func (f *FP) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return FingerprintSizeError{Got: len(data)}
	}
	copy(f[:], data)
	return nil
}

// ParseFP parses a hex-encoded fingerprint string.
func ParseFP(s string) (FP, error) {
	var fp FP
	if s == "" {
		return fp, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fp, fmt.Errorf("qconn: invalid fingerprint hex: %w", err)
	}
	if len(b) != 32 {
		return fp, FingerprintSizeError{Got: len(b)}
	}
	copy(fp[:], b)
	return fp, nil
}

// MustParseFP parses a hex-encoded fingerprint string, panicking on error.
func MustParseFP(s string) FP {
	fp, err := ParseFP(s)
	if err != nil {
		panic(err)
	}
	return fp
}

// FingerprintOf returns the SHA-256 fingerprint of a certificate.
func FingerprintOf(cert *x509.Certificate) FP {
	if cert == nil {
		return FP{}
	}
	return sha256.Sum256(cert.Raw)
}

// FingerprintHex returns the SHA-256 hash of the certificate's raw bytes as a hex string.
// Deprecated: Use FingerprintOf(cert).String() instead.
func FingerprintHex(cert *x509.Certificate) string {
	return FingerprintOf(cert).String()
}

// EncodeCertPEM converts an x509 certificate to PEM format.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// CreateCA creates a new self-signed Certificate Authority.
func CreateCA() (caCert *x509.Certificate, caKey *ecdsa.PrivateKey, err error) {
	caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "qconn Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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
// Note: Roles are managed server-side and are not embedded in certificates.
func CreateCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hostname string, isServer bool) (certPEM []byte, keyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname}, // Use SAN for modern validation.
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
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

	now := time.Now()
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
	// Since the client doesn't send this CA cert (it only uses the key to sign its leaf),
	// and the server generates its own copy for its pool, byte-for-byte identity of the
	// CA certificate itself is no longer required—only the Public Key must match.
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

// GenerateProvisioningIdentity creates a fresh leaf certificate signed by the derived CA.
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

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "provision"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
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

// SignCSR signs a certificate signing request with the CA and returns the certificate.
// The server never sees the client's private key.
// DEPRECATED: Use SignCSRWithValidation for new code to ensure hostname validation.
func SignCSR(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, csrPEM []byte, isServer bool) (certPEM []byte, err error) {
	return SignCSRWithValidation(caCert, caKey, csrPEM, "", isServer)
}

// SignCSRWithValidation signs a CSR after validating that it matches the expected hostname.
// If expectedHostname is non-empty, the CSR's CommonName and DNSNames must match it.
// This prevents identity spoofing where a client requests a certificate for a different identity.
func SignCSRWithValidation(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, csrPEM []byte, expectedHostname string, isServer bool) (certPEM []byte, err error) {
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

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(45 * 24 * time.Hour), // 45 days default validity
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
