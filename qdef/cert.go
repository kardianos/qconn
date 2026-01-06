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
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

var (
	// OIDProvisioningIdentity is a custom extension to identify provisioning certificates.
	OIDProvisioningIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
)

// Fingerprint returns the SHA-256 hash of the provided data.
func Fingerprint(data []byte) [32]byte {
	return sha256.Sum256(data)
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

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
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
func CreateCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hostname string, isServer bool) (certPEM []byte, keyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
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

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
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
