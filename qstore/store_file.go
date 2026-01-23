package qstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileDataStore implements DataStore using filesystem storage.
type FileDataStore struct {
	dir string
	mu  sync.RWMutex
}

var _ DataStore = (*FileDataStore)(nil)

// NewFileDataStore creates a new file-based data store.
func NewFileDataStore(dir string) (*FileDataStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("directory is required")
	}
	dir = os.Expand(dir, os.Getenv)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create data store directory: %w", err)
	}

	return &FileDataStore{dir: dir}, nil
}

// Get retrieves a value by key.
func (s *FileDataStore) Get(key string, decrypt bool) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.dir, key)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if decrypt && len(data) > 0 {
		decrypted, err := decryptValue(data)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", key, err)
		}
		return decrypted, nil
	}

	return data, nil
}

// Set stores a value by key.
func (s *FileDataStore) Set(key string, encrypt bool, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data := value
	if encrypt {
		encrypted, err := encryptValue(value)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", key, err)
		}
		data = encrypted
	}

	path := filepath.Join(s.dir, key)
	return atomicWriteFile(path, data, 0600)
}

// Path returns the storage location for display purposes.
func (s *FileDataStore) Path() string {
	return s.dir
}

// atomicWriteFile writes data to a temp file and renames it to the target path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	return os.Rename(tmpName, path)
}
