package qstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadKeyValue(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "simple text value",
			input: `key=T{value}`,
			want:  map[string]string{"key": "value"},
		},
		{
			name: "multiple keys",
			input: `
foo=T{bar}
baz=T{qux}
`,
			want: map[string]string{"foo": "bar", "baz": "qux"},
		},
		{
			name: "multi-line text value",
			input: `key=T{
line1
line2
line3
}`,
			want: map[string]string{"key": "line1\nline2\nline3"},
		},
		{
			name: "comments and empty lines",
			input: `
# this is a comment
key=T{value}

# another comment
`,
			want: map[string]string{"key": "value"},
		},
		{
			name:  "empty text value",
			input: `key=T{}`,
			want:  map[string]string{"key": ""},
		},
		{
			name:  "binary value single line",
			input: `key=B{SGVsbG8gV29ybGQ=}`,
			want:  map[string]string{"key": "Hello World"},
		},
		{
			name: "binary value multi-line",
			input: `key=B{
SGVsbG8g
V29ybGQ=
}`,
			want: map[string]string{"key": "Hello World"},
		},
		{
			name:  "text with brackets",
			input: `key=T{hello[world]}`,
			want:  map[string]string{"key": "hello[world]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv, err := readKeyValue(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("readKeyValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if len(kv) != len(tt.want) {
				t.Errorf("readKeyValue() got %d keys, want %d", len(kv), len(tt.want))
			}

			for k, want := range tt.want {
				got := string(kv[k])
				if got != want {
					t.Errorf("readKeyValue()[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestWriteKeyValue(t *testing.T) {
	tests := []struct {
		name  string
		input map[string][]byte
		check func(t *testing.T, output string)
	}{
		{
			name:  "simple text value",
			input: map[string][]byte{"key": []byte("value")},
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, `key=T{value}`) {
					t.Errorf("output should contain key=T{value}, got: %s", output)
				}
			},
		},
		{
			name:  "multi-line text value",
			input: map[string][]byte{"key": []byte("line1\nline2")},
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "key=T{") {
					t.Errorf("output should contain key=T{, got: %s", output)
				}
				if !strings.Contains(output, "line1\nline2") {
					t.Errorf("output should contain multi-line content, got: %s", output)
				}
			},
		},
		{
			name:  "text value with brackets allowed",
			input: map[string][]byte{"key": []byte("hello[world]")},
			check: func(t *testing.T, output string) {
				// Should use text encoding - brackets are now allowed
				if !strings.Contains(output, "key=T{hello[world]}") {
					t.Errorf("output should use text encoding for brackets, got: %s", output)
				}
			},
		},
		{
			name:  "binary value with braces",
			input: map[string][]byte{"key": []byte("hello{world}")},
			check: func(t *testing.T, output string) {
				// Should use binary encoding because of braces
				if !strings.Contains(output, "key=B{") {
					t.Errorf("output should use binary encoding for braces, got: %s", output)
				}
			},
		},
		{
			name:  "binary value with high bytes",
			input: map[string][]byte{"key": []byte{0x80, 0x81, 0x82}},
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "key=B{") {
					t.Errorf("output should use binary encoding for high bytes, got: %s", output)
				}
			},
		},
		{
			name:  "sorted keys",
			input: map[string][]byte{"z": []byte("1"), "a": []byte("2"), "m": []byte("3")},
			check: func(t *testing.T, output string) {
				aIdx := strings.Index(output, `a=T{2}`)
				mIdx := strings.Index(output, `m=T{3}`)
				zIdx := strings.Index(output, `z=T{1}`)
				if !(aIdx < mIdx && mIdx < zIdx) {
					t.Errorf("keys should be sorted, got: %s", output)
				}
			},
		},
		{
			name:  "long binary splits into multiple lines",
			input: map[string][]byte{"key": bytes.Repeat([]byte{0x80}, 100)},
			check: func(t *testing.T, output string) {
				// Should have multi-line binary format
				lines := strings.Split(output, "\n")
				foundOpenBrace := false
				foundCloseBrace := false
				for _, line := range lines {
					if strings.HasSuffix(line, "B{") {
						foundOpenBrace = true
					}
					if line == "}" {
						foundCloseBrace = true
					}
				}
				if !foundOpenBrace || !foundCloseBrace {
					t.Errorf("long binary should use multi-line format, got: %s", output)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeKeyValue(&buf, tt.input)
			if err != nil {
				t.Fatalf("writeKeyValue() error = %v", err)
			}
			tt.check(t, buf.String())
		})
	}
}

func TestKeyValueRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{"simple text", []byte("hello world")},
		{"multiline text", []byte("line1\nline2\nline3")},
		{"empty", []byte("")},
		{"text with brackets", []byte("hello[world]")},
		{"binary with braces", []byte("hello{world}")},
		{"high bytes", []byte{0x80, 0x81, 0x82, 0x83}},
		{"mixed content", []byte("text\x00with\x01nulls")},
		{"long binary", bytes.Repeat([]byte{0xFF}, 200)},
		{"PEM-like", []byte("-----BEGIN CERTIFICATE-----\nAABBCC\n-----END CERTIFICATE-----")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := keyValue{"key": tt.value}

			var buf bytes.Buffer
			if err := writeKeyValue(&buf, original); err != nil {
				t.Fatalf("writeKeyValue() error = %v", err)
			}

			parsed, err := readKeyValue(&buf)
			if err != nil {
				t.Fatalf("readKeyValue() error = %v", err)
			}

			if !bytes.Equal(parsed["key"], original["key"]) {
				t.Errorf("round-trip failed: got %q, want %q", parsed["key"], original["key"])
			}
		})
	}
}

func TestNeedsBinaryEncoding(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		binary bool
	}{
		{"simple text", []byte("hello"), false},
		{"with newline", []byte("hello\nworld"), false},
		{"with tab", []byte("hello\tworld"), false},
		{"with bracket [", []byte("hello[world"), false},
		{"with bracket ]", []byte("hello]world"), false},
		{"with brace {", []byte("hello{world"), true},
		{"with brace }", []byte("hello}world"), true},
		{"high byte", []byte{0x80}, true},
		{"null byte", []byte{0x00}, true},
		{"DEL", []byte{0x7f}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := needsBinaryEncoding(tt.input)
			if got != tt.binary {
				t.Errorf("needsBinaryEncoding() = %v, want %v", got, tt.binary)
			}
		})
	}
}

func TestConfigDataStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	// Create new store (file doesn't exist yet)
	store, err := NewConfigDataStore(path)
	if err != nil {
		t.Fatalf("NewConfigDataStore() error = %v", err)
	}

	// Get non-existent key
	data, err := store.Get("missing", false)
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if data != nil {
		t.Errorf("Get() = %v, want nil", data)
	}

	// Set a value
	if err := store.Set("key1", false, []byte("value1")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get the value back
	data, err = store.Get("key1", false)
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if string(data) != "value1" {
		t.Errorf("Get() = %q, want %q", data, "value1")
	}

	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("config file was not created")
	}

	// Create new store from existing file
	store2, err := NewConfigDataStore(path)
	if err != nil {
		t.Fatalf("NewConfigDataStore() error = %v", err)
	}

	// Verify data persisted
	data, err = store2.Get("key1", false)
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if string(data) != "value1" {
		t.Errorf("Get() = %q, want %q", data, "value1")
	}

	// Verify Path()
	if store.Path() != path {
		t.Errorf("Path() = %q, want %q", store.Path(), path)
	}
}

func TestConfigDataStoreEncryption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	store, err := NewConfigDataStore(path)
	if err != nil {
		t.Fatalf("NewConfigDataStore() error = %v", err)
	}

	plaintext := []byte("secret data")

	// Set with encryption
	if err := store.Set("secret", true, plaintext); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get without decryption - should get encrypted data
	encrypted, err := store.Get("secret", false)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Error("encrypted data should not equal plaintext")
	}

	// Get with decryption - should get original data
	decrypted, err := store.Get("secret", true)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// Verify encryption persists across store instances
	store2, err := NewConfigDataStore(path)
	if err != nil {
		t.Fatalf("NewConfigDataStore() error = %v", err)
	}

	decrypted2, err := store2.Get("secret", true)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted2, plaintext)
	}
}

func TestConfigDataStoreMultipleKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	store, err := NewConfigDataStore(path)
	if err != nil {
		t.Fatalf("NewConfigDataStore() error = %v", err)
	}

	// Set multiple keys
	keys := map[string][]byte{
		"cert":   []byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"),
		"key":    []byte("private key data"),
		"ca":     []byte("ca cert data"),
		"server": []byte("localhost:9443"),
	}

	for k, v := range keys {
		encrypt := k == "key" // Only encrypt the private key
		if err := store.Set(k, encrypt, v); err != nil {
			t.Fatalf("Set(%q) error = %v", k, err)
		}
	}

	// Reload and verify
	store2, err := NewConfigDataStore(path)
	if err != nil {
		t.Fatalf("NewConfigDataStore() error = %v", err)
	}

	for k, want := range keys {
		decrypt := k == "key"
		got, err := store2.Get(k, decrypt)
		if err != nil {
			t.Errorf("Get(%q) error = %v", k, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Get(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestConfigFileFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	store, err := NewConfigDataStore(path)
	if err != nil {
		t.Fatalf("NewConfigDataStore() error = %v", err)
	}

	// Set various types of data
	if err := store.Set("text", false, []byte("simple text")); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("multiline", false, []byte("line1\nline2")); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("binary", false, []byte{0x80, 0x81}); err != nil {
		t.Fatal(err)
	}

	// Read the file and check format
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	s := string(content)

	// Text should use T{...} format
	if !strings.Contains(s, "text=T{simple text}") {
		t.Errorf("text should use T{...} format, got:\n%s", s)
	}

	// Multiline should use T{\n...\n} format
	if !strings.Contains(s, "multiline=T{") || !strings.Contains(s, "line1\nline2") {
		t.Errorf("multiline should use T{...} format with newlines, got:\n%s", s)
	}

	// Binary should use B{...} format with base64
	if !strings.Contains(s, "binary=B{") {
		t.Errorf("binary should use B{...} format, got:\n%s", s)
	}
}
