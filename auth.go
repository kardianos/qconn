package qconn

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"go.etcd.io/bbolt"
)

var (
	bucketConfig     = []byte("config")
	bucketServerCert = []byte("server_cert")
	bucketClients    = []byte("clients")
	bucketAuthTokens = []byte("auth_tokens") // unredeemed auth tokens with expiry
	bucketTempAuth   = []byte("temp_auth")   // redeemed FP authorizations with expiry

	keyCAC     = []byte("ca_cert_pem")
	keyCAK     = []byte("ca_key_pem")
	keySrvC    = []byte("cert_pem")
	keySrvK    = []byte("key_pem")
	keySrvHost = []byte("hostname")
)

// authTokenRecord stores an unredeemed auth token.
type authTokenRecord struct {
	Token     TA        `cbor:"1,keyasint"`
	ExpiresAt time.Time `cbor:"2,keyasint"` // Must be redeemed by this time
}

// tempAuthRecord stores a redeemed authorization for a fingerprint.
type tempAuthRecord struct {
	FP        FP        `cbor:"1,keyasint"`
	ExpiresAt time.Time `cbor:"2,keyasint"` // Authorization expires at this time
}

// RoleConfig defines what message types a role can provide (handle) and submit (send).
type RoleConfig struct {
	// Provide lists message types this role can handle (receive requests for).
	Provide []string
	// Submit lists message types this role can send (make requests for).
	Submit []string
}

// BoltAuthConfig configures the BoltAuthManager.
type BoltAuthConfig struct {
	// DBPath is the path to the bbolt database file.
	// If empty, defaults to "auth.db" in the current directory.
	DBPath string

	// ServerHostname is the hostname for the server certificate.
	// If empty, defaults to the system hostname.
	ServerHostname string

	// ProvisionTokens are the shared secrets used for provisioning.
	// Each token creates a derived CA for provisioning certificate validation.
	ProvisionTokens []string

	// CACert and CAKey allow injecting an existing CA.
	// If nil, a new CA is created or loaded from the database.
	CACert *x509.Certificate
	CAKey  *ecdsa.PrivateKey

	// Roles maps role names to their permissions.
	// Each role defines what message types it can provide and submit.
	Roles map[string]*RoleConfig

	// OnCleanupError is called when background cleanup encounters an error.
	// If nil, cleanup errors are silently ignored.
	OnCleanupError func(error)
}

// ClientRecord stores information about a provisioned client.
type ClientRecord struct {
	Fingerprint        FP           `cbor:"1,keyasint"`
	Hostname           string       `cbor:"2,keyasint"`
	Status             ClientStatus `cbor:"3,keyasint"`
	CreatedAt          time.Time    `cbor:"4,keyasint"`
	ExpiresAt          time.Time    `cbor:"5,keyasint"`
	UpdatedAt          time.Time    `cbor:"6,keyasint"`
	MachineIP          string       `cbor:"7,keyasint,omitempty"` // Client's IP from its own perspective
	RemoteIP           string       `cbor:"8,keyasint,omitempty"` // Client's IP from server's perspective
	Devices            []DeviceInfo `cbor:"9,keyasint,omitempty"`
	MsgTypes           []string     `cbor:"10,keyasint,omitempty"` // Message types the client advertises it can handle
	AuthorizedMsgTypes []string     `cbor:"11,keyasint,omitempty"` // Message types the client is authorized to handle
	Roles              []string     `cbor:"12,keyasint,omitempty"` // Roles assigned to this client
	Online             bool         `cbor:"13,keyasint,omitempty"` // Set by server based on connection state
}

// ClientRecordFilter specifies filter criteria for ListClientRecord.
type ClientRecordFilter struct {
	Status *ClientStatus // Filter by auth status (nil = any)
	Online *bool         // Filter by online status (nil = any, applied post-merge by server)
	Roles  []string      // Filter by roles (client has any of these, nil = any)
}

// BoltAuthManager implements AuthManager using bbolt for persistence.
type BoltAuthManager struct {
	db             *bbolt.DB
	caCert         *x509.Certificate
	caKey          *ecdsa.PrivateKey
	serverHostname string

	// Role-based access control.
	roles map[string]*RoleConfig

	// Provisioning support.
	provisionTokens  map[string]bool
	provisioningPool *x509.CertPool
	provisionCerts   map[string]*provisionCertEntry // SNI -> cert entry

	// Server certificate cache.
	mu         sync.RWMutex
	serverCert *tls.Certificate

	// Cleanup goroutine control.
	cleanupDone    chan struct{}
	onCleanupError func(error)
}

// provisionCertEntry holds a provisioning server certificate with its CA.
type provisionCertEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
	ca        tls.Certificate
}

var _ AuthManager = (*BoltAuthManager)(nil)
var _ ClientStore = (*BoltAuthManager)(nil)

// NewBoltAuthManager creates a new AuthManager backed by bbolt.
// Returns the manager and a bool indicating if this is a new database (first init).
// On first init, callers should use CreateAuthToken to generate tokens for initial
// admin clients to self-authorize.
func NewBoltAuthManager(cfg BoltAuthConfig) (*BoltAuthManager, bool, error) {
	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = "auth.db"
	}

	// Ensure directory exists.
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, false, fmt.Errorf("create data directory: %w", err)
		}
	}

	// Check if database file exists (before opening).
	_, statErr := os.Stat(dbPath)
	isNew := os.IsNotExist(statErr)

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, false, fmt.Errorf("open database: %w", err)
	}

	hostname := cfg.ServerHostname
	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			db.Close()
			return nil, false, fmt.Errorf("get hostname: %w", err)
		}
	}

	m := &BoltAuthManager{
		db:               db,
		serverHostname:   hostname,
		roles:            cfg.Roles,
		provisionTokens:  make(map[string]bool),
		provisioningPool: x509.NewCertPool(),
		provisionCerts:   make(map[string]*provisionCertEntry),
		onCleanupError:   cfg.OnCleanupError,
	}

	// Create buckets. Check if CA bucket already has data to detect new DB.
	var hadCA bool
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, bucket := range [][]byte{bucketConfig, bucketServerCert, bucketClients, bucketAuthTokens, bucketTempAuth} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		// Check if CA already exists.
		b := tx.Bucket(bucketConfig)
		if b.Get(keyCAC) != nil {
			hadCA = true
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, false, fmt.Errorf("create buckets: %w", err)
	}

	// If we thought it was new but CA exists, it's not actually new.
	if hadCA {
		isNew = false
	}

	// Load or create CA.
	if cfg.CACert != nil && cfg.CAKey != nil {
		m.caCert = cfg.CACert
		m.caKey = cfg.CAKey
		if err := m.saveCA(); err != nil {
			db.Close()
			return nil, false, fmt.Errorf("save CA: %w", err)
		}
	} else {
		if err := m.loadOrCreateCA(); err != nil {
			db.Close()
			return nil, false, fmt.Errorf("load/create CA: %w", err)
		}
	}

	// Setup provisioning tokens.
	for _, token := range cfg.ProvisionTokens {
		m.provisionTokens[token] = true

		// Create derived CA for this token.
		ca, err := GenerateDerivedCA(token)
		if err != nil {
			continue
		}
		leaf, err := x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			continue
		}
		m.provisioningPool.AddCert(leaf)

		// Generate provisioning server cert.
		sni := ProvisioningServerName(token)
		serverCert, expiresAt, err := GenerateProvisioningServerCert(ca, sni)
		if err != nil {
			continue
		}
		m.provisionCerts[sni] = &provisionCertEntry{
			cert:      &serverCert,
			expiresAt: expiresAt,
			ca:        ca,
		}
	}

	return m, isNew, nil
}

func (m *BoltAuthManager) loadOrCreateCA() error {
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketConfig)
		certPEM := b.Get(keyCAC)
		keyPEM := b.Get(keyCAK)
		if certPEM == nil || keyPEM == nil {
			return nil // Need to create.
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("failed to decode CA cert PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA cert: %w", err)
		}

		block, _ = pem.Decode(keyPEM)
		if block == nil {
			return fmt.Errorf("failed to decode CA key PEM")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA key: %w", err)
		}

		m.caCert = cert
		m.caKey = key
		return nil
	})
	if err != nil {
		return err
	}

	if m.caCert == nil {
		cert, key, err := CreateCA()
		if err != nil {
			return fmt.Errorf("create CA: %w", err)
		}
		m.caCert = cert
		m.caKey = key
		return m.saveCA()
	}

	return nil
}

func (m *BoltAuthManager) saveCA() error {
	certPEM := EncodeCertPEM(m.caCert)
	keyBytes, err := x509.MarshalECPrivateKey(m.caKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketConfig)
		if err := b.Put(keyCAC, certPEM); err != nil {
			return err
		}
		return b.Put(keyCAK, keyPEM)
	})
}

// ServerCertificate returns the server's TLS certificate for the given SNI.
// For provisioning requests (matching a derived SNI), returns the provisioning cert.
// For all other requests, returns the main server certificate.
func (m *BoltAuthManager) ServerCertificate(sni string) (*tls.Certificate, error) {
	// Check for provisioning SNI first.
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.provisionCerts[sni]; ok {
		// Check if cert is expiring soon.
		if timeNow().Add(time.Hour).After(entry.expiresAt) {
			newCert, expiresAt, err := GenerateProvisioningServerCert(entry.ca, sni)
			if err == nil {
				m.provisionCerts[sni] = &provisionCertEntry{
					cert:      &newCert,
					expiresAt: expiresAt,
					ca:        entry.ca,
				}
				return &newCert, nil
			}
		}
		return entry.cert, nil
	}

	// Return main server certificate.
	return m.getOrCreateServerCert()
}

func (m *BoltAuthManager) getOrCreateServerCert() (*tls.Certificate, error) {
	// Check cache.
	if m.serverCert != nil && !m.isCertExpiringSoon(m.serverCert) {
		return m.serverCert, nil
	}

	// Try to load from database.
	var certPEM, keyPEM []byte
	var storedHostname string
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketServerCert)
		certPEM = b.Get(keySrvC)
		keyPEM = b.Get(keySrvK)
		if h := b.Get(keySrvHost); h != nil {
			storedHostname = string(h)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	// Use stored cert if valid.
	if certPEM != nil && keyPEM != nil && storedHostname == m.serverHostname {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err == nil && !m.isCertExpiringSoon(&cert) {
			m.serverCert = &cert
			return m.serverCert, nil
		}
	}

	// Create new server certificate.
	certPEM, keyPEM, err = CreateCert(m.caCert, m.caKey, m.serverHostname, true)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}

	// Store in database.
	err = m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketServerCert)
		if err := b.Put(keySrvC, certPEM); err != nil {
			return err
		}
		if err := b.Put(keySrvK, keyPEM); err != nil {
			return err
		}
		return b.Put(keySrvHost, []byte(m.serverHostname))
	})
	if err != nil {
		return nil, fmt.Errorf("store server cert: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	m.serverCert = &cert
	return m.serverCert, nil
}

func (m *BoltAuthManager) isCertExpiringSoon(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return timeNow().Add(time.Hour).After(leaf.NotAfter)
}

// VerifyClientCertificate verifies a client certificate.
// Provisioning certificates are verified against the provisioning CA pool.
// Normal certificates are verified against the main CA.
func (m *BoltAuthManager) VerifyClientCertificate(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return ErrNoClientCert
	}

	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("qconn: failed to parse client cert: %w", err)
	}

	// Check for provisioning certificate.
	if isProvisioningCert(leaf) {
		opts := x509.VerifyOptions{
			Roots:     m.provisioningPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := leaf.Verify(opts); err != nil {
			return fmt.Errorf("qconn: invalid provisioning certificate: %w", err)
		}
		return nil
	}

	// Verify against main CA.
	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("qconn: failed to verify client certificate: %w", err)
	}

	return nil
}

// RootCertPEM returns the root CA certificate in PEM format.
func (m *BoltAuthManager) RootCertPEM() ([]byte, error) {
	return EncodeCertPEM(m.caCert), nil
}

// generateAuthToken creates a secure random token string.
func generateAuthToken() (TA, error) {
	b := make([]byte, taSize)
	if _, err := rand.Read(b); err != nil {
		return TA{}, err
	}
	return *(*TA)(b), nil
}

// CreateAuthToken creates a new auth token that must be redeemed within 24 hours.
// Once redeemed, the authorization is valid for an additional 24 hours.
// Returns the generated token string.
func (m *BoltAuthManager) CreateAuthToken() (string, error) {
	token, err := generateAuthToken()
	if err != nil {
		return "", err
	}
	rec := authTokenRecord{
		Token:     token,
		ExpiresAt: timeNow().Add(24 * time.Hour),
	}

	err = m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthTokens)
		data, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(token[:], data)
	})
	if err != nil {
		return "", err
	}
	return token.String(), nil
}

// ValidAuthToken validates and redeems a self-authorization token.
// Auth tokens must be redeemed within 24 hours of creation.
// Once redeemed, the fingerprint is granted 24 hours of temporary authorization
// for system commands only.
// Returns the expiration time of the temporary authorization if valid.
func (m *BoltAuthManager) ValidAuthToken(tokenText string, fp FP) (bool, time.Time, error) {
	ta, err := ParseTA(tokenText)
	if err != nil {
		return false, time.Time{}, err
	}
	now := timeNow()
	expiresAt := now.Add(24 * time.Hour)

	var valid bool
	err = m.db.Update(func(tx *bbolt.Tx) error {
		// Check if token exists and is not expired.
		tokenBucket := tx.Bucket(bucketAuthTokens)
		data := tokenBucket.Get(ta[:])
		if data == nil {
			return nil // Token not found.
		}

		var rec authTokenRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			// Corrupted record, delete it.
			return tokenBucket.Delete(ta[:])
		}

		// Check if token has expired (must be redeemed within 24 hours).
		if now.After(rec.ExpiresAt) {
			// Token expired, delete it.
			return tokenBucket.Delete(ta[:])
		}

		// Token is valid - redeem it (delete from tokens bucket).
		if err := tokenBucket.Delete(ta[:]); err != nil {
			return err
		}

		// Create temporary authorization for this FP.
		authBucket := tx.Bucket(bucketTempAuth)
		authRec := tempAuthRecord{
			FP:        fp,
			ExpiresAt: expiresAt,
		}
		authData, err := cbor.Marshal(authRec)
		if err != nil {
			return err
		}
		if err := authBucket.Put(fp[:], authData); err != nil {
			return err
		}

		valid = true
		return nil
	})
	if err != nil {
		return false, time.Time{}, err
	}
	return valid, expiresAt, nil
}

// HasTempAuth checks if a fingerprint has temporary authorization for system commands.
// Returns true and the expiration time if authorized.
func (m *BoltAuthManager) hasTempAuth(fp FP) (bool, error) {
	now := timeNow()
	var valid bool

	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketTempAuth)
		data := b.Get(fp[:])
		if data == nil {
			return nil
		}

		var rec tempAuthRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			return nil // Corrupted record.
		}

		if now.After(rec.ExpiresAt) {
			return nil // Expired.
		}

		valid = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return valid, nil
}

// SignProvisioningCSR signs a CSR for a new client.
func (m *BoltAuthManager) SignProvisioningCSR(csrPEM []byte, hostname string) ([]byte, error) {
	certPEM, err := SignCSR(m.caCert, m.caKey, csrPEM, hostname, false)
	if err != nil {
		return nil, err
	}

	// Parse certificate to store client record.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode signed certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signed cert: %w", err)
	}

	// Store client record as unauthenticated - provisioning only grants the certificate.
	// The client must be authorized by an admin before it can communicate.
	now := time.Now()
	fp := FingerprintOf(leaf)
	rec := ClientRecord{
		Fingerprint: fp,
		Hostname:    hostname,
		Status:      StatusUnauthenticated,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   leaf.NotAfter,
	}

	err = m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(fp[:], data)
	})
	if err != nil {
		return nil, fmt.Errorf("store client record: %w", err)
	}

	return certPEM, nil
}

// SignRenewalCSR signs a CSR for certificate renewal.
// The caller is responsible for checking client status and updating the client record.
func (m *BoltAuthManager) SignRenewalCSR(csrPEM []byte, hostname string) ([]byte, error) {
	return SignCSR(m.caCert, m.caKey, csrPEM, hostname, false)
}

// RootCertPool returns a certificate pool containing the root CA.
func (m *BoltAuthManager) RootCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	return pool
}

// Close stops the cleanup goroutine and closes the database.
func (m *BoltAuthManager) Close() error {
	if m.cleanupDone != nil {
		close(m.cleanupDone)
	}
	return m.db.Close()
}

// GetClientStatus returns the authorization status of a client.
// Returns StatusUnknown if the client is not found or has expired.
func (m *BoltAuthManager) GetClientStatus(fp FP) (ClientStatus, error) {
	var status ClientStatus
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
		if data == nil {
			status = StatusUnknown
			return nil
		}

		var rec ClientRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			status = StatusUnknown
			return nil
		}

		// Check if expired.
		if timeNow().After(rec.ExpiresAt) {
			status = StatusUnknown
			return nil
		}

		status = rec.Status
		return nil
	})
	// Check for temp auth.
	if status != StatusAuthenticated {
		tempAuth, err := m.hasTempAuth(fp)
		if err != nil {
			return status, err
		}
		if tempAuth {
			return StatusAuthenticated, nil
		}
	}
	return status, err
}

// SetClientStatus updates a client's authorization status.
// If the client doesn't exist, a new record is created.
// If status is StatusRevoked, authorizedMsgTypes is ignored (all types revoked).
func (m *BoltAuthManager) SetClientStatus(fp FP, status ClientStatus, expiresAt time.Time, authorizedMsgTypes []string) error {
	if status == StatusUnknown {
		return fmt.Errorf("cannot set status to unknown")
	}

	now := time.Now()
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])

		var rec ClientRecord
		if data != nil {
			if err := cbor.Unmarshal(data, &rec); err != nil {
				// Corrupted record, create new one.
				rec = ClientRecord{
					Fingerprint: fp,
					CreatedAt:   now,
				}
			}
		} else {
			rec = ClientRecord{
				Fingerprint: fp,
				CreatedAt:   now,
			}
		}

		rec.Status = status
		rec.ExpiresAt = expiresAt
		rec.UpdatedAt = now
		if status == StatusRevoked {
			rec.AuthorizedMsgTypes = nil
		} else {
			rec.AuthorizedMsgTypes = authorizedMsgTypes
		}

		newData, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(fp[:], newData)
	})
}

// GetClientRecord returns the full client record for a fingerprint.
// Returns nil if the client is not found or has expired.
func (m *BoltAuthManager) GetClientRecord(fp FP) (*ClientRecord, error) {
	var rec *ClientRecord
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
		if data == nil {
			return nil
		}

		var r ClientRecord
		if err := cbor.Unmarshal(data, &r); err != nil {
			return nil // Treat corrupted record as not found.
		}

		// Check if expired.
		if timeNow().After(r.ExpiresAt) {
			return nil
		}

		rec = &r
		return nil
	})
	return rec, err
}

// UpdateClientInfo updates the client info fields (MachineIP, Devices, etc).
// Only updates the specified fields; does not change status or expiry.
func (m *BoltAuthManager) UpdateClientInfo(fp FP, info *ClientInfoUpdate) error {
	now := time.Now()
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
		if data == nil {
			return ErrNotConnected
		}

		var rec ClientRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			return err
		}

		// Update fields from info.
		if info.MachineIP != "" {
			rec.MachineIP = info.MachineIP
		}
		if info.RemoteIP != "" {
			rec.RemoteIP = info.RemoteIP
		}
		if info.Devices != nil {
			rec.Devices = info.Devices
		}
		if info.MsgTypes != nil {
			rec.MsgTypes = info.MsgTypes
		}
		rec.UpdatedAt = now

		newData, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(fp[:], newData)
	})
}

// SetClientRoles updates a client's assigned roles.
func (m *BoltAuthManager) SetClientRoles(fp FP, roles []string) error {
	now := time.Now()
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
		if data == nil {
			return ErrNotConnected
		}

		var rec ClientRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			return err
		}

		rec.Roles = roles
		rec.UpdatedAt = now

		newData, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(fp[:], newData)
	})
}

// Allow checks if an action is permitted between originator and target.
// A zero target FP indicates a system message.
//
//  1. For system targets: admin messages require admin role + temp auth; other messages are allowed.
//  2. For client-to-client: check originator has the claimed role.
//  3. Check that the role is allowed to submit the msgType.
//  4. Check that target FP has a role that can provide the msgType.
//  5. If all checks pass, allow communication.
func (m *BoltAuthManager) Allow(act Action, originator FP, target FP, msgType string, role string) (bool, error) {
	isSystemTarget := target.IsZero()

	if isSystemTarget {
		if !IsAdminMessageType(msgType) {
			// Non-admin system messages are always allowed.
			return true, nil
		}

		// ADMIN SYSTEM message - requires temp auth OR RBAC permission.
		hasTempAuth, err := m.hasTempAuth(originator)
		if err != nil {
			return false, err
		}
		if hasTempAuth {
			return true, nil
		}

		// No temp auth - check RBAC for admin message.
		if len(m.roles) == 0 {
			// No RBAC configured and no temp auth - deny admin message.
			return false, nil
		}

		// RBAC is enabled - check if originator has role that can submit this admin msgType.
		if len(role) == 0 {
			return false, nil
		}
		originRec, err := m.GetClientRecord(originator)
		if err != nil {
			return false, err
		}
		if originRec == nil {
			return false, nil
		}
		if !hasRole(originRec.Roles, role) {
			return false, nil
		}
		if !m.roleCanSubmit(role, msgType) {
			return false, nil
		}
		// Admin message allowed via RBAC.
		return true, nil
	}

	// Client-to-client routing.
	// If no roles are configured, allow all client-to-client communication.
	if len(m.roles) == 0 {
		return true, nil
	}

	// Role-based access control is enabled.
	if len(role) == 0 {
		return false, nil // Role is required when RBAC is enabled.
	}

	// Check originator FP has the claimed role.
	originRec, err := m.GetClientRecord(originator)
	if err != nil {
		return false, err
	}
	if originRec == nil {
		return false, nil // Originator not found.
	}
	if !hasRole(originRec.Roles, role) {
		return false, nil // Originator doesn't have the claimed role.
	}

	// Check role can submit this msgType.
	if !m.roleCanSubmit(role, msgType) {
		return false, nil
	}

	// Check target FP has a role that can provide the msgType.
	targetRec, err := m.GetClientRecord(target)
	if err != nil {
		return false, err
	}
	if targetRec == nil {
		return false, nil // Target not found.
	}
	if !m.targetCanProvide(targetRec.Roles, msgType) {
		return false, nil // Target doesn't have a role that can provide this msgType.
	}

	return true, nil
}

// hasRole checks if the roles slice contains the given role.
func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// hasAnyRole checks if the clientRoles slice contains any of the filterRoles.
func hasAnyRole(clientRoles, filterRoles []string) bool {
	for _, fr := range filterRoles {
		for _, cr := range clientRoles {
			if cr == fr {
				return true
			}
		}
	}
	return false
}

// targetCanProvide checks if any of the target's roles can provide the msgType.
func (m *BoltAuthManager) targetCanProvide(targetRoles []string, msgType string) bool {
	if m.roles == nil {
		return false
	}
	for _, role := range targetRoles {
		rc := m.roles[role]
		if rc == nil {
			continue
		}
		for _, mt := range rc.Provide {
			if mt == msgType {
				return true
			}
		}
	}
	return false
}

// roleCanSubmit checks if the given role is allowed to submit (send) the msgType.
func (m *BoltAuthManager) roleCanSubmit(role, msgType string) bool {
	if m.roles == nil {
		return false
	}
	rc := m.roles[role]
	if rc == nil {
		return false
	}
	for _, mt := range rc.Submit {
		if mt == msgType {
			return true
		}
	}
	return false
}

// ListClients returns all client records.
func (m *BoltAuthManager) ListClients() ([]ClientRecord, error) {
	var clients []ClientRecord
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(k, v []byte) error {
			var rec ClientRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				return nil // Skip corrupted records.
			}
			clients = append(clients, rec)
			return nil
		})
	})
	return clients, err
}

// ListClientRecord returns all non-expired client records matching the filter.
// The filter can specify Status and Roles (persisted fields).
// The Online field filter is not applied here - it should be applied by the caller
// after merging with connection state.
// If filter is nil, returns all non-expired records.
func (m *BoltAuthManager) ListClientRecord(filter *ClientRecordFilter) ([]*ClientRecord, error) {
	var records []*ClientRecord
	now := timeNow()

	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(k, v []byte) error {
			rec := new(ClientRecord)
			if err := cbor.Unmarshal(v, rec); err != nil {
				return nil // Skip corrupted records.
			}

			// Skip expired records.
			if now.After(rec.ExpiresAt) {
				return nil
			}

			// Apply filters.
			if filter != nil {
				if filter.Status != nil && rec.Status != *filter.Status {
					return nil
				}
				if len(filter.Roles) > 0 && !hasAnyRole(rec.Roles, filter.Roles) {
					return nil
				}
			}

			records = append(records, rec)
			return nil
		})
	})
	return records, err
}

// StartCleanup starts the periodic cleanup of expired client records.
// Call this after creating the BoltAuthManager to enable automatic cleanup.
// The cleanup interval determines how often expired records are removed.
func (m *BoltAuthManager) StartCleanup(interval time.Duration) {
	if m.cleanupDone != nil {
		return // Already running.
	}
	m.cleanupDone = make(chan struct{})
	go m.cleanupLoop(interval)
}

func (m *BoltAuthManager) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.cleanupDone:
			return
		case <-ticker.C:
			if _, err := m.CleanupExpired(); err != nil && m.onCleanupError != nil {
				m.onCleanupError(err)
			}
		}
	}
}

// CleanupExpired removes all expired records from the database.
// This includes expired client records, auth tokens, and temp auth records.
// Returns the total number of records removed.
func (m *BoltAuthManager) CleanupExpired() (int, error) {
	now := timeNow()
	var expiredClients [][]byte
	var expiredTokens [][]byte
	var expiredTempAuth [][]byte

	// First, find all expired records.
	err := m.db.View(func(tx *bbolt.Tx) error {
		// Check clients bucket.
		b := tx.Bucket(bucketClients)
		if err := b.ForEach(func(k, v []byte) error {
			var rec ClientRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				// Corrupted record, mark for deletion.
				key := make([]byte, len(k))
				copy(key, k)
				expiredClients = append(expiredClients, key)
				return nil
			}
			if now.After(rec.ExpiresAt) {
				key := make([]byte, len(k))
				copy(key, k)
				expiredClients = append(expiredClients, key)
			}
			return nil
		}); err != nil {
			return err
		}

		// Check auth tokens bucket.
		b = tx.Bucket(bucketAuthTokens)
		if err := b.ForEach(func(k, v []byte) error {
			var rec authTokenRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				// Corrupted record, mark for deletion.
				key := make([]byte, len(k))
				copy(key, k)
				expiredTokens = append(expiredTokens, key)
				return nil
			}
			if now.After(rec.ExpiresAt) {
				key := make([]byte, len(k))
				copy(key, k)
				expiredTokens = append(expiredTokens, key)
			}
			return nil
		}); err != nil {
			return err
		}

		// Check temp auth bucket.
		b = tx.Bucket(bucketTempAuth)
		return b.ForEach(func(k, v []byte) error {
			var rec tempAuthRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				// Corrupted record, mark for deletion.
				key := make([]byte, len(k))
				copy(key, k)
				expiredTempAuth = append(expiredTempAuth, key)
				return nil
			}
			if now.After(rec.ExpiresAt) {
				key := make([]byte, len(k))
				copy(key, k)
				expiredTempAuth = append(expiredTempAuth, key)
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}

	total := len(expiredClients) + len(expiredTokens) + len(expiredTempAuth)
	if total == 0 {
		return 0, nil
	}

	// Delete expired records.
	err = m.db.Update(func(tx *bbolt.Tx) error {
		// Delete expired clients.
		b := tx.Bucket(bucketClients)
		for _, key := range expiredClients {
			if err := b.Delete(key); err != nil {
				return err
			}
		}

		// Delete expired auth tokens.
		b = tx.Bucket(bucketAuthTokens)
		for _, key := range expiredTokens {
			if err := b.Delete(key); err != nil {
				return err
			}
		}

		// Delete expired temp auth.
		b = tx.Bucket(bucketTempAuth)
		for _, key := range expiredTempAuth {
			if err := b.Delete(key); err != nil {
				return err
			}
		}

		return nil
	})
	return total, err
}
