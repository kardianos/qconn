//go:build windows

package qstore

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RegistryDataStore implements DataStore using Windows registry.
// Encryption uses Windows DPAPI for protection at rest.
type RegistryDataStore struct {
	hive    registry.Key
	keyPath string
}

var _ DataStore = (*RegistryDataStore)(nil)

// NewRegistryDataStore creates a Windows registry-based data store.
// Path format: "HIVE/path/to/key" where HIVE is one of:
//   - LM or LOCAL_MACHINE for HKEY_LOCAL_MACHINE (services)
//   - CU or CURRENT_USER for HKEY_CURRENT_USER (user apps)
//
// Example: "LM/SOFTWARE/qconn/client" or "CU/SOFTWARE/qconn/admin"
func NewRegistryDataStore(path string) (*RegistryDataStore, error) {
	// Convert forward slashes to backslashes.
	path = strings.ReplaceAll(path, "/", `\`)

	// Split off the hive prefix.
	hiveStr, keyPath, found := strings.Cut(path, `\`)
	if !found {
		return nil, fmt.Errorf("invalid registry path: missing hive prefix (use LM/ or CU/)")
	}

	var hive registry.Key
	switch strings.ToUpper(hiveStr) {
	case "LM", "LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "CU", "CURRENT_USER":
		hive = registry.CURRENT_USER
	default:
		return nil, fmt.Errorf("invalid registry hive: %s (use LM, LOCAL_MACHINE, CU, or CURRENT_USER)", hiveStr)
	}

	// Create the registry key if it doesn't exist.
	key, _, err := registry.CreateKey(hive, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return nil, fmt.Errorf("create registry key: %w", err)
	}
	key.Close()

	return &RegistryDataStore{
		hive:    hive,
		keyPath: keyPath,
	}, nil
}

func (s *RegistryDataStore) Get(key string, decrypt bool) ([]byte, error) {
	regKey, err := registry.OpenKey(s.hive, s.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, nil
	}
	defer regKey.Close()

	data, _, err := regKey.GetBinaryValue(key)
	if err != nil {
		return nil, nil
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

func (s *RegistryDataStore) Set(key string, encrypt bool, value []byte) error {
	regKey, _, err := registry.CreateKey(s.hive, s.keyPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer regKey.Close()

	data := value
	if encrypt {
		encrypted, err := encryptValue(value)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", key, err)
		}
		data = encrypted
	}

	return regKey.SetBinaryValue(key, data)
}

func (s *RegistryDataStore) Path() string {
	var hiveStr string
	switch s.hive {
	case registry.LOCAL_MACHINE:
		hiveStr = "HKLM"
	case registry.CURRENT_USER:
		hiveStr = "HKCU"
	default:
		hiveStr = "UNKNOWN"
	}
	return hiveStr + `\` + s.keyPath
}
