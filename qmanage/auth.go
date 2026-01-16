package qmanage

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	bucketConfig     = []byte("config")
	bucketServerCert = []byte("server_cert")
	bucketClients    = []byte("clients")
	bucketRoles      = []byte("roles")

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
	dbPath         string
	caCert         *x509.Certificate
	caKey          *ecdsa.PrivateKey
	serverCert     *tls.Certificate
	serverHostname string

	mu      sync.RWMutex
	signals map[qdef.FP]chan struct{}

	// Cleanup goroutine control.
	cleanupStop chan struct{}
	cleanupDone chan struct{}

	// Backup goroutine control.
	backupStop chan struct{}
	backupDone chan struct{}
}

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
		dbPath:         dbPath,
		serverHostname: cfg.ServerHostname,
		signals:        make(map[qdef.FP]chan struct{}),
	}

	if m.serverHostname == "" {
		m.serverHostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("get hostname: %w", err)
		}
	}

	// Create buckets.
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, bucket := range [][]byte{bucketConfig, bucketServerCert, bucketClients, bucketRoles} {
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

	// Start backup goroutine if enabled.
	if cfg.BackupInterval > 0 {
		m.backupStop = make(chan struct{})
		m.backupDone = make(chan struct{})
		go m.backupLoop(cfg.BackupInterval)
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
func (m *BoltAuthManager) GetStatus(fp qdef.FP) (qdef.ClientStatus, error) {
	var status qdef.ClientStatus
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
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

// WaitFor blocks until the authorization status changes or context is cancelled.
// Returns ctx.Err() on context cancellation, nil if status changed.
func (m *BoltAuthManager) WaitFor(ctx context.Context, fp qdef.FP) error {
	m.mu.Lock()
	sig, ok := m.signals[fp]
	if !ok {
		sig = make(chan struct{})
		m.signals[fp] = sig
	}
	m.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-sig:
		return nil
	}
}

func (m *BoltAuthManager) triggerSignal(fp qdef.FP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sig, ok := m.signals[fp]; ok {
		close(sig)
		delete(m.signals, fp)
	}
}

// cleanupSignal removes a signal channel for a fingerprint without triggering it.
func (m *BoltAuthManager) cleanupSignal(fp qdef.FP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.signals, fp)
}

// SignProvisioningCSR signs a CSR for initial provisioning.
func (m *BoltAuthManager) SignProvisioningCSR(csrPEM []byte, hostname string, roles []string) ([]byte, error) {
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
	fp := qdef.FingerprintOf(leaf)

	// Store client record.
	rec := ClientRecord{
		Fingerprint:    fp,
		Hostname:       hostname,
		Status:         qdef.StatusUnauthorized,
		RequestedRoles: roles,
		CreatedAt:      time.Now(),
		ExpiresAt:      leaf.NotAfter,
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

	m.triggerSignal(fp)
	return certPEM, nil
}

// SignRenewalCSR signs a CSR for certificate renewal.
// The hostname is validated against the original client record to prevent identity changes.
func (m *BoltAuthManager) SignRenewalCSR(csrPEM []byte, fp qdef.FP) ([]byte, error) {
	// Load existing client record.
	var oldRec ClientRecord
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
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
	newFP := qdef.FingerprintOf(leaf)

	// Update client record: delete old, create new with same status and roles.
	newRec := ClientRecord{
		Fingerprint:    newFP,
		Hostname:       oldRec.Hostname,
		Status:         oldRec.Status,
		RequestedRoles: oldRec.RequestedRoles,
		CreatedAt:      oldRec.CreatedAt,
		ExpiresAt:      leaf.NotAfter,
	}

	err = m.db.Update(func(tx *bbolt.Tx) error {
		clients := tx.Bucket(bucketClients)

		// Delete old fingerprint.
		if err := clients.Delete(fp[:]); err != nil {
			return err
		}

		// Store new fingerprint.
		data, err := cbor.Marshal(newRec)
		if err != nil {
			return err
		}
		return clients.Put(newFP[:], data)
	})
	if err != nil {
		return nil, fmt.Errorf("update client record: %w", err)
	}

	// Clean up old fingerprint's signal channel (if any).
	m.cleanupSignal(fp)
	m.triggerSignal(newFP)
	return certPEM, nil
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

// SetClientStatus updates a client's status.
func (m *BoltAuthManager) SetClientStatus(fp qdef.FP, status qdef.ClientStatus) error {
	if fp.IsZero() {
		return errors.New("missing fingerprint to set client status")
	}
	err := m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
		if data == nil {
			// Create new record if it doesn't exist.
			rec := ClientRecord{
				Fingerprint: fp,
				Status:      status,
				CreatedAt:   time.Now(),
			}
			data, err := cbor.Marshal(rec)
			if err != nil {
				return err
			}
			return b.Put(fp[:], data)
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
		return b.Put(fp[:], newData)
	})
	if err != nil {
		return err
	}
	m.triggerSignal(fp)
	return nil
}

// UpdateClientAddr updates a client's connection info when they connect.
// Sets the address, marks them as online, updates LastSeen, and sets hostname if empty.
// If no record exists, creates one with the provided hostname.
func (m *BoltAuthManager) UpdateClientAddr(fp qdef.FP, online bool, addr netip.AddrPort, hostname string) error {
	now := time.Now()
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])

		var rec ClientRecord
		if data == nil {
			// Create new record for client connecting without prior provisioning.
			rec = ClientRecord{
				Fingerprint: fp,
				Hostname:    hostname,
				Status:      qdef.StatusUnauthorized,
				CreatedAt:   now,
				LastAddr:    addr,
				Online:      online,
				LastSeen:    now,
			}
		} else {
			if err := cbor.Unmarshal(data, &rec); err != nil {
				return fmt.Errorf("unmarshal client record: %w", err)
			}
			rec.LastAddr = addr
			rec.Online = online
			rec.LastSeen = now
			if rec.Hostname == "" && hostname != "" {
				rec.Hostname = hostname
			}
		}

		newData, err := cbor.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(fp[:], newData)
	})
}

// ClearAllOnline marks all clients as offline.
// Call this on server startup to clear stale online status from previous runs.
func (m *BoltAuthManager) ClearAllOnline() error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(k, v []byte) error {
			var rec ClientRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				return nil // Skip corrupted records.
			}
			if !rec.Online {
				return nil // Already offline.
			}
			rec.Online = false
			newData, err := cbor.Marshal(rec)
			if err != nil {
				return err
			}
			return b.Put(k, newData)
		})
	})
}

// ListClients returns client records matching the filter criteria.
// Pass an empty filter to return all clients.
// Returns an empty map if an error occurs during iteration.
func (m *BoltAuthManager) ListClients(filter ClientFilter) map[qdef.FP]ClientRecord {
	result := make(map[qdef.FP]ClientRecord)
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)

		// If fingerprints specified, do direct lookups instead of iterating all.
		if len(filter.Fingerprints) > 0 {
			for _, fp := range filter.Fingerprints {
				v := b.Get(fp[:])
				if v == nil {
					continue
				}
				var rec ClientRecord
				if err := cbor.Unmarshal(v, &rec); err != nil {
					continue
				}
				// Filter by status if specified.
				if filter.Status != nil && rec.Status != *filter.Status {
					continue
				}
				result[fp] = rec
			}
			return nil
		}

		// No fingerprint filter, iterate all clients.
		return b.ForEach(func(k, v []byte) error {
			var rec ClientRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				// Skip corrupted entries but continue iteration.
				return nil
			}

			// Filter by status if specified.
			if filter.Status != nil && rec.Status != *filter.Status {
				return nil
			}

			var fp qdef.FP
			copy(fp[:], k)
			result[fp] = rec
			return nil
		})
	})
	if err != nil {
		return make(map[qdef.FP]ClientRecord)
	}
	return result
}

// ListClientsInfo returns clients as ClientInfo slice (implements AuthorizationManager).
// If fingerprints is non-empty, only clients with matching fingerprints are returned.
func (m *BoltAuthManager) ListClientsInfo(showUnauthorized bool, fingerprints []qdef.FP) []qdef.ClientInfo {
	filter := ClientFilter{Fingerprints: fingerprints}
	if !showUnauthorized {
		status := qdef.StatusAuthorized
		filter.Status = &status
	}

	records := m.ListClients(filter)
	result := make([]qdef.ClientInfo, 0, len(records))

	for fp, rec := range records {
		// Roles are the client's requested roles if they're authorized.
		var roles []string
		if rec.Status == qdef.StatusAuthorized {
			roles = rec.RequestedRoles
		}

		info := qdef.ClientInfo{
			Fingerprint:    fp,
			Hostname:       rec.Hostname,
			Status:         rec.Status,
			Authorized:     rec.Status == qdef.StatusAuthorized,
			CreatedAt:      rec.CreatedAt,
			ExpiresAt:      rec.ExpiresAt,
			LastAddr:       rec.LastAddr,
			Roles:          roles,
			RequestedRoles: rec.RequestedRoles,
			Online:         rec.Online,
			LastSeen:       rec.LastSeen,
		}
		result = append(result, info)
	}

	return result
}

// DeleteClient removes a client record.
// Also cleans up any signal channels associated with the client.
func (m *BoltAuthManager) DeleteClient(fp qdef.FP) error {
	err := m.db.Update(func(tx *bbolt.Tx) error {
		clients := tx.Bucket(bucketClients)
		return clients.Delete(fp[:])
	})
	if err != nil {
		return err
	}
	// Clean up signal channel.
	m.cleanupSignal(fp)
	return nil
}

// Close releases resources and stops background goroutines.
func (m *BoltAuthManager) Close() error {
	if m.cleanupStop != nil {
		close(m.cleanupStop)
		<-m.cleanupDone
	}
	if m.backupStop != nil {
		close(m.backupStop)
		<-m.backupDone
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
			_, _ = m.CleanupExpiredClients()
		}
	}
}

// CleanupExpiredClients removes client records for certificates
// that have expired. This prevents the database from growing indefinitely.
// Returns the number of clients removed and any database error encountered.
func (m *BoltAuthManager) CleanupExpiredClients() (int, error) {
	now := time.Now()
	var removed int

	// Collect expired fingerprints.
	var expiredFPs []qdef.FP
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		return b.ForEach(func(k, v []byte) error {
			var rec ClientRecord
			if err := cbor.Unmarshal(v, &rec); err != nil {
				return nil // Skip corrupted records.
			}
			if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
				var fp qdef.FP
				copy(fp[:], k)
				expiredFPs = append(expiredFPs, fp)
			}
			return nil
		})
	})
	if err != nil {
		return 0, fmt.Errorf("scan expired clients: %w", err)
	}

	if len(expiredFPs) == 0 {
		return 0, nil
	}

	// Delete expired records.
	err = m.db.Update(func(tx *bbolt.Tx) error {
		clients := tx.Bucket(bucketClients)

		for _, fp := range expiredFPs {
			if err := clients.Delete(fp[:]); err == nil {
				removed++
			}
		}
		return nil
	})
	if err != nil {
		return removed, fmt.Errorf("delete expired clients: %w", err)
	}

	// Clean up signal channels.
	for _, fp := range expiredFPs {
		m.cleanupSignal(fp)
	}

	return removed, nil
}

// RootCertPEM returns the root CA certificate in PEM format.
func (m *BoltAuthManager) RootCertPEM() []byte {
	return qdef.EncodeCertPEM(m.caCert)
}

// SetClientExpiry updates a client's expiration time.
// This is primarily useful for testing cleanup behavior.
func (m *BoltAuthManager) SetClientExpiry(fp qdef.FP, expiresAt time.Time) error {
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketClients)
		data := b.Get(fp[:])
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
		return b.Put(fp[:], newData)
	})
}

// backupLoop periodically backs up the database.
func (m *BoltAuthManager) backupLoop(interval time.Duration) {
	defer close(m.backupDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.backupStop:
			return
		case <-ticker.C:
			m.Backup()
		}
	}
}

// Backup creates a backup of the database.
// The backup is written to auth.db.backup next to the active database.
// Returns an error if the backup fails.
func (m *BoltAuthManager) Backup() error {
	backupPath := m.dbPath + ".backup"
	tmpPath := backupPath + ".tmp"

	// Write to temp file first, then rename for atomicity.
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	defer os.Remove(tmpPath)

	err = m.db.View(func(tx *bbolt.Tx) error {
		_, err := tx.WriteTo(f)
		return err
	})
	if err != nil {
		f.Close()
		return fmt.Errorf("write backup: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync backup: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close backup: %w", err)
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, backupPath); err != nil {
		return fmt.Errorf("rename backup: %w", err)
	}

	return nil
}
