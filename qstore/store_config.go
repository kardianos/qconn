package qstore

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// keyValue holds key-value pairs from a simple config file.
// Format:
//
//	key=T{text value}
//	key=T{
//	multi-line text
//	}
//	key=B{base64encoded}
//	key=B{
//	base64encoded
//	over multiple lines
//	}
//
// Text encoding uses T{...}, binary encoding uses B{...} with base64.
// Text is used when value contains only printable ASCII and no braces.
// Binary is used otherwise. Leading/trailing newlines in text are trimmed.
type keyValue map[string][]byte

// needsBinaryEncoding returns true if the value should use binary (base64) encoding.
func needsBinaryEncoding(data []byte) bool {
	for _, b := range data {
		// Non-printable ASCII (except newline, tab, carriage return)
		if b < 0x20 && b != '\n' && b != '\t' && b != '\r' {
			return true
		}
		// DEL or high bytes
		if b >= 0x7f {
			return true
		}
		// Brace characters that would conflict with our format
		if b == '{' || b == '}' {
			return true
		}
	}
	return false
}

// isMultiline returns true if the value contains newlines.
func isMultiline(data []byte) bool {
	return bytes.Contains(data, []byte{'\n'})
}

// loadKeyValue loads a config file from path.
func loadKeyValue(path string) (keyValue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readKeyValue(f)
}

func readKeyValue(r io.Reader) (keyValue, error) {
	kv := make(keyValue)
	scanner := bufio.NewScanner(r)

	var multiLineKey string
	var multiLineValue bytes.Buffer
	var isBinary bool

	for scanner.Scan() {
		line := scanner.Text()

		if multiLineKey != "" {
			// In multi-line mode.
			if line == "}" {
				var value []byte
				if isBinary {
					// Decode base64
					decoded, err := base64.StdEncoding.DecodeString(multiLineValue.String())
					if err != nil {
						return nil, fmt.Errorf("decode base64 for key %q: %w", multiLineKey, err)
					}
					value = decoded
				} else {
					// Text value - trim leading/trailing newlines
					value = bytes.Trim(multiLineValue.Bytes(), "\n")
				}
				bb := make([]byte, len(value))
				copy(bb, value)
				kv[multiLineKey] = bb
				multiLineKey = ""
				multiLineValue.Reset()
			} else {
				if multiLineValue.Len() > 0 {
					multiLineValue.WriteByte('\n')
				}
				multiLineValue.WriteString(line)
			}
			continue
		}

		// Skip empty lines and comments.
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if len(value) == 0 {
			continue
		}

		// Check for multi-line markers
		if value == "T{" {
			multiLineKey = key
			isBinary = false
			continue
		}
		if value == "B{" {
			multiLineKey = key
			isBinary = true
			continue
		}

		// Single-line value
		if strings.HasPrefix(value, "T{") && strings.HasSuffix(value, "}") {
			// Text encoding
			kv[key] = []byte(value[2 : len(value)-1])
		} else if strings.HasPrefix(value, "B{") && strings.HasSuffix(value, "}") {
			// Binary encoding
			encoded := value[2 : len(value)-1]
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("decode base64 for key %q: %w", key, err)
			}
			kv[key] = decoded
		}
	}

	return kv, scanner.Err()
}

// saveKeyValue saves a config to path.
func saveKeyValue(path string, kv keyValue) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if err := writeKeyValue(tmp, kv); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}

	if err := tmp.Chmod(0600); err != nil {
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

func writeKeyValue(w io.Writer, kv keyValue) error {
	keyList := make([]string, 0, len(kv))
	for key := range kv {
		keyList = append(keyList, key)
	}
	sort.Strings(keyList)

	for _, key := range keyList {
		value := kv[key]
		binary := needsBinaryEncoding(value)
		multiline := false

		if binary {
			// Binary is multiline if encoded length > 60
			encoded := base64.StdEncoding.EncodeToString(value)
			multiline = len(encoded) > 60
		} else {
			multiline = isMultiline(value)
		}

		var err error
		if binary {
			if multiline {
				err = writeBinaryMultiline(w, key, value)
			} else {
				err = writeBinarySingleLine(w, key, value)
			}
		} else {
			if multiline {
				err = writeTextMultiline(w, key, value)
			} else {
				err = writeTextSingleLine(w, key, value)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func writeTextSingleLine(w io.Writer, key string, value []byte) error {
	_, err := fmt.Fprintf(w, "%s=T{%s}\n\n", key, value)
	return err
}

func writeTextMultiline(w io.Writer, key string, value []byte) error {
	_, err := fmt.Fprintf(w, "%s=T{\n%s\n}\n\n", key, value)
	return err
}

func writeBinarySingleLine(w io.Writer, key string, value []byte) error {
	encoded := base64.StdEncoding.EncodeToString(value)
	_, err := fmt.Fprintf(w, "%s=B{%s}\n\n", key, encoded)
	return err
}

func writeBinaryMultiline(w io.Writer, key string, value []byte) error {
	encoded := base64.StdEncoding.EncodeToString(value)
	if _, err := fmt.Fprintf(w, "%s=B{\n", key); err != nil {
		return err
	}

	// Break into 60-character lines
	for i := 0; i < len(encoded); i += 60 {
		end := i + 60
		if end > len(encoded) {
			end = len(encoded)
		}
		if _, err := fmt.Fprintf(w, "%s\n", encoded[i:end]); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "}\n\n")
	return err
}

// ConfigDataStore implements DataStore using a simple config file.
type ConfigDataStore struct {
	path     string
	instance keyValue
}

var _ DataStore = (*ConfigDataStore)(nil)

// NewConfigDataStore creates a config file-based data store.
// The path can start with ~ to indicate the user's home directory.
func NewConfigDataStore(configPath string) (*ConfigDataStore, error) {
	configPath = expandPath(configPath)
	kv, err := loadKeyValue(configPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if kv == nil {
		kv = make(keyValue)
	}
	return &ConfigDataStore{
		path:     configPath,
		instance: kv,
	}, nil
}

// expandPath expands ~ and environment variables in a path.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	return os.Expand(path, os.Getenv)
}

// isPrintableASCII returns true if r is a printable ASCII character.
func isPrintableASCII(r rune) bool {
	return r >= 0x20 && r < 0x7f || r == '\n' || r == '\t' || r == '\r'
}

// isTextSafe returns true if the string can be safely stored as text.
func isTextSafe(s string) bool {
	for _, r := range s {
		if !isPrintableASCII(r) {
			return false
		}
		if r == '{' || r == '}' {
			return false
		}
	}
	return true
}

// IsPrintable returns true if all runes in s are printable.
func IsPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\n' && r != '\t' && r != '\r' {
			return false
		}
	}
	return true
}

func (s *ConfigDataStore) Get(key string, decrypt bool) ([]byte, error) {
	data := s.instance[key]
	if len(data) == 0 {
		return nil, nil
	}

	if decrypt && len(data) > 0 {
		decrypted, err := decryptValue(data)
		if err != nil {
			return nil, err
		}
		return decrypted, nil
	}

	return data, nil
}

func (s *ConfigDataStore) Set(key string, encrypt bool, value []byte) error {
	data := value
	if encrypt {
		encrypted, err := encryptValue(value)
		if err != nil {
			return err
		}
		data = encrypted
	}

	s.instance[key] = data
	return saveKeyValue(s.path, s.instance)
}

func (s *ConfigDataStore) Path() string {
	return s.path
}
