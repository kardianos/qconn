package qstore

// DataStore provides simple key-value storage for credentials and other data.
// Platform-specific implementations can use files, Windows registry with DPAPI, etc.
type DataStore interface {
	// Get retrieves a value by key. Returns nil, nil if not found.
	// If decrypt is true, the value is decrypted before returning.
	Get(key string, decrypt bool) ([]byte, error)

	// Set stores a value by key.
	// If encrypt is true, the value is encrypted before storing.
	Set(key string, encrypt bool, value []byte) error

	// Path returns the storage location for display purposes.
	Path() string
}
