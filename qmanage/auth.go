package qmanage

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"go.etcd.io/bbolt"
)

var (
	bucketConfig         = []byte("config")
	bucketServerCert     = []byte("server_cert")
	bucketClients        = []byte("clients")
	bucketRoles          = []byte("roles")
	bucketAuthorizations = []byte("authorizations")

	keyCAC     = []byte("ca_cert_pem")
	keyCAK     = []byte("ca_key_pem")
	keySrvC    = []byte("cert_pem")
	keySrvK    = []byte("key_pem")
	keySrvHost = []byte("hostname")
)

// DefaultCleanupInterval is the default interval for cleaning up expired clients.
const DefaultCleanupInterval = 6 * time.Hour

// BoltAuthManager implements AuthManager using bbolt for persistence.
//
// SECURITY NOTE: The CA and server private keys are stored in the bbolt database.
// Encryption at rest is the caller's responsibility. Consider using filesystem-level
// encryption (e.g., LUKS, BitLocker) or encrypting the data directory.
type BoltAuthManager struct {
	db             *bbolt.DB
	caCert         *x509.Certificate
	caKey          *ecdsa.PrivateKey
	serverCert     *tls.Certificate
	serverHostname string

	mu      sync.RWMutex
	signals map[string]chan struct{}

	// Cleanup goroutine control.
	cleanupStop chan struct{}
	cleanupDone chan struct{}
}

var _ AuthManager = (*BoltAuthManager)(nil)
var _ qdef.AuthorizationManager = (*BoltAuthManager)(nil)

// NewAuthManager creates a new AuthManager with bbolt storage.
func NewAuthManager(cfg AuthManagerConfig) (*BoltAuthManager, error) {
	if err := validateAppName(cfg.AppName); err != nil {
		return nil, err
	}

	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = defaultServerDir(cfg.AppName)
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "auth.db")
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	m := &BoltAuthManager{
		db:             db,
		serverHostname: cfg.ServerHostname,
		signals:        make(map[string]chan struct{}),
	}

	if m.serverHostname == "" {
		m.serverHostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("get hostname: %w", err)
		}
	}

	// Create buckets.
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, bucket := range [][]byte{bucketConfig, bucketServerCert, bucketClients, bucketRoles, bucketAuthorizations} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create buckets: %w", err)
	}

	// Load or create CA.
	if cfg.CACert != nil && cfg.CAKey != nil {
		m.caCert = cfg.CACert
		m.caKey = cfg.CAKey
		if err := m.saveCA(); err != nil {
			db.Close()
			return nil, fmt.Errorf("save CA: %w", err)
		}
	} else {
		if err := m.loadOrCreateCA(); err != nil {
			db.Close()
			return nil, fmt.Errorf("load/create CA: %w", err)
		}
	}

	// Start cleanup goroutine unless disabled.
	cleanupInterval := cfg.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = DefaultCleanupInterval
	}
	if cleanupInterval > 0 {
		m.cleanupStop = make(chan struct{})
		m.cleanupDone = make(chan struct{})
		go m.cleanupLoop(cleanupInterval)
	}

	return m, nil
}

func (m *BoltAuthManager) loadOrCreateCA() error {
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketConfig)
		certPEM := b.Get(keyCAC)
		keyPEM := b.Get(keyCAK)
		if certPEM == nil || keyPEM == nil {
			return nil // Need to create.
		}

		// Parse certificate.
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("failed to decode CA cert PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA cert: %w", err)
		}

		// Parse key.
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
		// Create new CA.
		cert, key, err := qdef.CreateCA()
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
	certPEM := qdef.EncodeCertPEM(m.caCert)
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

// GetStatus returns the authorization status of a client.
// Returns StatusRevoked if the client's certificate has expired.
func (m *BoltAuthManager) GetStatus(cert *x509.Certificate) (qdef.ClientStatus, error) {
	fp := qdef.FingerprintHex(cert)

	var status qdef.ClientStatus
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get([]byte(fp))
		if data == nil {
			status = qdef.StatusUnprovisioned
			return nil
		}
		var rec ClientRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("unmarshal client record: %w", err)
		}
		// Check if certificate has expired.
		if !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt) {
			status = qdef.StatusRevoked
			return nil
		}
		status = rec.Status
		return nil
	})
	return status, err
}

// GetSignal returns a channel that is closed when the client's status changes.
func (m *BoltAuthManager) GetSignal(cert *x509.Certificate) <-chan struct{} {
	fp := qdef.FingerprintHex(cert)
	m.mu.Lock()
	defer m.mu.Unlock()

	sig, ok := m.signals[fp]
	if !ok {
		sig = make(chan struct{})
		m.signals[fp] = sig
	}
	return sig
}

func (m *BoltAuthManager) triggerSignal(fp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sig, ok := m.signals[fp]; ok {
		close(sig)
		delete(m.signals, fp)
	}
}

// cleanupSignal removes a signal channel for a fingerprint without triggering it.
func (m *BoltAuthManager) cleanupSignal(fp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.signals, fp)
}

// AuthorizeRoles filters requested roles based on static authorization.
func (m *BoltAuthManager) AuthorizeRoles(fingerprint string, requested []string) []string {
	allowed := m.GetStaticAuthorization(fingerprint)
	if len(allowed) == 0 {
		return nil
	}

	allowedMap := make(map[string]bool)
	for _, r := range allowed {
		allowedMap[r] = true
	}

	var authorized []string
	for _, req := range requested {
		if allowedMap[req] {
			authorized = append(authorized, req)
		}
	}
	return authorized
}

// SignProvisioningCSR signs a CSR for initial provisioning.
func (m *BoltAuthManager) SignProvisioningCSR(csrPEM []byte, hostname string) ([]byte, error) {
	certPEM, err := qdef.SignCSRWithValidation(m.caCert, m.caKey, csrPEM, hostname, false)
	if err != nil {
		return nil, err
	}

	// Parse certificate to get fingerprint.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode signed cert")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signed cert: %w", err)
	}
	fp := qdef.FingerprintHex(leaf)

	// Store client record.
	rec := ClientRecord{
		Fingerprint: fp,
		Hostname:    hostname,
		Status:      qdef.StatusUnauthorized,
		CreatedAt:   time.Now(),
		ExpiresAt:   leaf.NotAfter,
	}

	err = m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(fp), data)
	})
	if err != nil {
		return nil, fmt.Errorf("store client record: %w", err)
	}

	m.triggerSignal(fp)
	return certPEM, nil
}

// SignRenewalCSR signs a CSR for certificate renewal.
// The hostname is validated against the original client record to prevent identity changes.
func (m *BoltAuthManager) SignRenewalCSR(csrPEM []byte, fingerprint string) ([]byte, error) {
	// Load existing client record.
	var oldRec ClientRecord
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get([]byte(fingerprint))
		if data == nil {
			return qdef.ErrUnknownClient
		}
		return cbor.Unmarshal(data, &oldRec)
	})
	if err != nil {
		return nil, err
	}

	if oldRec.Status == qdef.StatusRevoked {
		return nil, qdef.ErrClientRevoked
	}

	// Sign the CSR, validating against the ORIGINAL hostname to prevent identity changes.
	certPEM, err := qdef.SignCSRWithValidation(m.caCert, m.caKey, csrPEM, oldRec.Hostname, false)
	if err != nil {
		return nil, err
	}

	// Parse new certificate.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode signed cert")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signed cert: %w", err)
	}
	newFP := qdef.FingerprintHex(leaf)

	// Update client record: delete old, create new with same status.
	newRec := ClientRecord{
		Fingerprint: newFP,
		Hostname:    oldRec.Hostname,
		Status:      oldRec.Status,
		CreatedAt:   oldRec.CreatedAt,
		ExpiresAt:   leaf.NotAfter,
	}

	err = m.db.Update(func(tx *bbolt.Tx) error {
		clients := tx.Bucket(bucketClients)
		auths := tx.Bucket(bucketAuthorizations)

		// Delete old fingerprint.
		if err := clients.Delete([]byte(fingerprint)); err != nil {
			return err
		}

		// Store new fingerprint.
		data, err := cbor.Marshal(newRec)
		if err != nil {
			return err
		}
		if err := clients.Put([]byte(newFP), data); err != nil {
			return err
		}

		// Migrate authorizations.
		oldAuth := auths.Get([]byte(fingerprint))
		if oldAuth != nil {
			if err := auths.Delete([]byte(fingerprint)); err != nil {
				return err
			}
			if err := auths.Put([]byte(newFP), oldAuth); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("update client record: %w", err)
	}

	// Clean up old fingerprint's signal channel (if any).
	m.cleanupSignal(fingerprint)
	m.triggerSignal(newFP)
	return certPEM, nil
}

// Revoke marks a client as revoked.
func (m *BoltAuthManager) Revoke(id qdef.Identity) error {
	if id.Fingerprint.IsZero() {
		return qdef.ErrFingerprintEmpty
	}
	return m.SetClientStatus(id.Fingerprint.String(), qdef.StatusRevoked)
}

// RootCert returns the root CA certificate.
func (m *BoltAuthManager) RootCert() *x509.Certificate {
	return m.caCert
}

// ServerCertificate returns the server's TLS certificate.
// The certificate hostname is configured via AuthManagerConfig.ServerHostname.
func (m *BoltAuthManager) ServerCertificate() (tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.serverCert != nil {
		return *m.serverCert, nil
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
		return tls.Certificate{}, fmt.Errorf("load server cert: %w", err)
	}

	// Only use stored cert if hostname matches.
	if certPEM != nil && keyPEM != nil && storedHostname == m.serverHostname {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err == nil {
			m.serverCert = &cert
			return cert, nil
		}
	}

	// Create new server certificate with configured hostname.
	certPEM, keyPEM, err = qdef.CreateCert(m.caCert, m.caKey, m.serverHostname, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server cert: %w", err)
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
		return tls.Certificate{}, fmt.Errorf("store server cert: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	m.serverCert = &cert
	return cert, nil
}

// SetRoleDef stores a role definition.
func (m *BoltAuthManager) SetRoleDef(name string, config RoleConfig) error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRoles)
		data, err := cbor.Marshal(config)
		if err != nil {
			return err
		}
		return b.Put([]byte(name), data)
	})
}

// GetRoleDef retrieves a role definition.
// Returns (config, true) if found, (RoleConfig{}, false) if not found or on error.
func (m *BoltAuthManager) GetRoleDef(name string) (RoleConfig, bool) {
	var config RoleConfig
	var found bool
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRoles)
		data := b.Get([]byte(name))
		if data == nil {
			return nil
		}
		if err := cbor.Unmarshal(data, &config); err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return RoleConfig{}, false
	}
	return config, found
}

// DeleteRoleDef removes a role definition.
func (m *BoltAuthManager) DeleteRoleDef(name string) error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRoles)
		return b.Delete([]byte(name))
	})
}

// ListRoleDefs returns all role definitions.
// Returns an empty map if an error occurs during iteration.
func (m *BoltAuthManager) ListRoleDefs() map[string]RoleConfig {
	result := make(map[string]RoleConfig)
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRoles)
		return b.ForEach(func(k, v []byte) error {
			var config RoleConfig
			if err := cbor.Unmarshal(v, &config); err != nil {
				// Skip corrupted entries but continue iteration.
				return nil
			}
			result[string(k)] = config
			return nil
		})
	})
	if err != nil {
		return make(map[string]RoleConfig)
	}
	return result
}

// SetStaticAuthorization sets the roles for a client.
func (m *BoltAuthManager) SetStaticAuthorization(fingerprint string, roles []string) error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthorizations)
		data, err := cbor.Marshal(roles)
		if err != nil {
			return err
		}
		return b.Put([]byte(fingerprint), data)
	})
}

// GetStaticAuthorization retrieves the roles for a client.
// Returns nil if the client has no authorizations or on error.
func (m *BoltAuthManager) GetStaticAuthorization(fingerprint string) []string {
	var roles []string
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthorizations)
		data := b.Get([]byte(fingerprint))
		if data == nil {
			return nil
		}
		return cbor.Unmarshal(data, &roles)
	})
	if err != nil {
		return nil
	}
	return roles
}

// RemoveStaticAuthorization removes roles for a client.
func (m *BoltAuthManager) RemoveStaticAuthorization(fingerprint string) error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthorizations)
		return b.Delete([]byte(fingerprint))
	})
}

// ListAuthorizations returns all client authorizations.
// Returns an empty map if an error occurs during iteration.
func (m *BoltAuthManager) ListAuthorizations() map[string][]string {
	result := make(map[string][]string)
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAuthorizations)
		return b.ForEach(func(k, v []byte) error {
			var roles []string
			if err := cbor.Unmarshal(v, &roles); err != nil {
				// Skip corrupted entries but continue iteration.
				return nil
			}
			result[string(k)] = roles
			return nil
		})
	})
	if err != nil {
		return make(map[string][]string)
	}
	return result
}

// SetClientStatus updates a client's status.
func (m *BoltAuthManager) SetClientStatus(fingerprint string, status qdef.ClientStatus) error {
	err := m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get([]byte(fingerprint))
		if data == nil {
			// Create new record if it doesn't exist.
			rec := ClientRecord{
				Fingerprint: fingerprint,
				Status:      status,
				CreatedAt:   time.Now(),
			}
			data, err := cbor.Marshal(rec)
			if err != nil {
				return err
			}
			return b.Put([]byte(fingerprint), data)
		}

		var rec ClientRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("unmarshal client record: %w", err)
		}
		rec.Status = status
		newData, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(fingerprint), newData)
	})
	if err != nil {
		return err
	}
	m.triggerSignal(fingerprint)
	return nil
}

// UpdateClientAddr updates a client's last known connection address.
// This should be called when a client connects to track their IP address.
func (m *BoltAuthManager) UpdateClientAddr(fingerprint string, addr netip.AddrPort) error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get([]byte(fingerprint))
		if data == nil {
			return qdef.ErrUnknownClient
		}

		var rec ClientRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("unmarshal client record: %w", err)
		}
		rec.LastAddr = addr
		newData, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(fingerprint), newData)
	})
}

// ListClients returns all client records.
// Returns an empty map if an error occurs during iteration.
func (m *BoltAuthManager) ListClients() map[string]ClientRecord {
	result := make(map[string]ClientRecord)
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(k, v []byte) error {
			var rec ClientRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				// Skip corrupted entries but continue iteration.
				return nil
			}
			result[string(k)] = rec
			return nil
		})
	})
	if err != nil {
		return make(map[string]ClientRecord)
	}
	return result
}

// DeleteClient removes a client record and its authorizations.
// Also cleans up any signal channels associated with the client.
func (m *BoltAuthManager) DeleteClient(fingerprint string) error {
	err := m.db.Update(func(tx *bbolt.Tx) error {
		clients := tx.Bucket(bucketClients)
		auths := tx.Bucket(bucketAuthorizations)

		if err := clients.Delete([]byte(fingerprint)); err != nil {
			return err
		}
		return auths.Delete([]byte(fingerprint))
	})
	if err != nil {
		return err
	}
	// Clean up signal channel.
	m.cleanupSignal(fingerprint)
	return nil
}

// Close releases resources and stops the cleanup goroutine.
func (m *BoltAuthManager) Close() error {
	if m.cleanupStop != nil {
		close(m.cleanupStop)
		<-m.cleanupDone
	}
	return m.db.Close()
}

// cleanupLoop periodically removes expired client records.
func (m *BoltAuthManager) cleanupLoop(interval time.Duration) {
	defer close(m.cleanupDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.cleanupStop:
			return
		case <-ticker.C:
			m.CleanupExpiredClients()
		}
	}
}

// CleanupExpiredClients removes client records and authorizations for certificates
// that have expired. This prevents the revocation list from growing indefinitely.
// Returns the number of clients removed.
func (m *BoltAuthManager) CleanupExpiredClients() int {
	now := time.Now()
	var removed int

	// Collect expired fingerprints.
	var expiredFPs []string
	_ = m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(k, v []byte) error {
			var rec ClientRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				return nil // Skip corrupted records.
			}
			if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
				expiredFPs = append(expiredFPs, string(k))
			}
			return nil
		})
	})

	if len(expiredFPs) == 0 {
		return 0
	}

	// Delete expired records.
	_ = m.db.Update(func(tx *bbolt.Tx) error {
		clients := tx.Bucket(bucketClients)
		auths := tx.Bucket(bucketAuthorizations)

		for _, fp := range expiredFPs {
			if err := clients.Delete([]byte(fp)); err == nil {
				removed++
			}
			// Also remove any authorizations for this fingerprint.
			_ = auths.Delete([]byte(fp))
		}
		return nil
	})

	// Clean up signal channels.
	for _, fp := range expiredFPs {
		m.cleanupSignal(fp)
	}

	return removed
}

// RootCertPEM returns the root CA certificate in PEM format.
func (m *BoltAuthManager) RootCertPEM() []byte {
	return qdef.EncodeCertPEM(m.caCert)
}

// SetClientExpiry updates a client's expiration time.
// This is primarily useful for testing cleanup behavior.
func (m *BoltAuthManager) SetClientExpiry(fingerprint string, expiresAt time.Time) error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get([]byte(fingerprint))
		if data == nil {
			return qdef.ErrUnknownClient
		}

		var rec ClientRecord
		if err := cbor.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("unmarshal client record: %w", err)
		}
		rec.ExpiresAt = expiresAt
		newData, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(fingerprint), newData)
	})
}
