package qdef

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Test vectors from BIP-173.
// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

func TestBech32InvalidStrings(t *testing.T) {
	// Invalid bech32 strings from BIP-173.
	invalidStrings := []struct {
		s      string
		reason string
	}{
		{"\x201nwldj5", "HRP character out of range"},
		{"\x7f1axkwrx", "HRP character out of range"},
		{"pzry9x0s0muk", "No separator character"},
		{"1pzry9x0s0muk", "Empty HRP"},
		{"x1b4n0q5v", "Invalid data character"},
		{"li1dgmt3", "Too short checksum"},
		{"de1lg7wt\xff", "Invalid character in checksum"},
		{"A1G7SGD8", "checksum calculated with uppercase form of HRP"},
		{"10a06t8", "Empty HRP"},
		{"1qzzfhee", "Empty HRP"},
	}

	for _, tc := range invalidStrings {
		_, _, err := Bech32Decode(tc.s)
		if err == nil {
			t.Errorf("Bech32Decode(%q) should have failed (%s)", tc.s, tc.reason)
		}
	}
}

func TestBech32EncodeKnownVectors(t *testing.T) {
	// Test encoding known data - verify round-trip.
	tests := []struct {
		hrp  string
		data []byte
	}{
		// Empty data.
		{"a", []byte{}},
		// 16-byte data (fingerprint size).
		{"qc", []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
		// Various sizes.
		{"test", []byte{0x01, 0x02, 0x03}},
		{"bc", []byte{0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6}},
	}

	for _, tc := range tests {
		encoded, err := Bech32Encode(tc.hrp, tc.data)
		if err != nil {
			t.Errorf("Bech32Encode(%q, %x) failed: %v", tc.hrp, tc.data, err)
			continue
		}

		// Decode and verify round-trip.
		hrp, data, err := Bech32Decode(encoded)
		if err != nil {
			t.Errorf("Bech32Decode(%q) failed: %v", encoded, err)
			continue
		}
		if hrp != strings.ToLower(tc.hrp) {
			t.Errorf("Round-trip HRP mismatch: got %q, want %q", hrp, strings.ToLower(tc.hrp))
		}
		if !bytes.Equal(data, tc.data) {
			t.Errorf("Round-trip data mismatch: got %x, want %x", data, tc.data)
		}

		t.Logf("Bech32Encode(%q, %x) = %q", tc.hrp, tc.data, encoded)
	}
}

func TestBech32DecodeValidStrings(t *testing.T) {
	// Valid bech32 strings - test they decode without error
	// and can be re-encoded (checksum verification).
	validStrings := []string{
		"A12UEL5L",
		"a12uel5l",
		"?1ezyfcl",
	}

	for _, s := range validStrings {
		hrp, data, err := Bech32Decode(s)
		if err != nil {
			t.Errorf("Bech32Decode(%q) failed: %v", s, err)
			continue
		}

		// Re-encode and verify checksum matches.
		encoded, err := Bech32Encode(hrp, data)
		if err != nil {
			t.Errorf("Bech32Encode(%q, %x) failed: %v", hrp, data, err)
			continue
		}

		// The re-encoded string should have valid checksum (decode should work).
		_, _, err = Bech32Decode(encoded)
		if err != nil {
			t.Errorf("Re-encoded string %q failed to decode: %v", encoded, err)
		}
	}
}

func TestBech32DecodeKnownVectors(t *testing.T) {
	// Test decoding with known expected data.
	tests := []struct {
		s            string
		expectedHRP  string
		expectedData string // hex encoded
	}{
		{"a12uel5l", "a", ""},
	}

	for _, tc := range tests {
		hrp, data, err := Bech32Decode(tc.s)
		if err != nil {
			t.Errorf("Bech32Decode(%q) failed: %v", tc.s, err)
			continue
		}
		if hrp != tc.expectedHRP {
			t.Errorf("Bech32Decode(%q) HRP = %q, want %q", tc.s, hrp, tc.expectedHRP)
		}
		expectedData, _ := hex.DecodeString(tc.expectedData)
		if !bytes.Equal(data, expectedData) {
			t.Errorf("Bech32Decode(%q) data = %x, want %x", tc.s, data, expectedData)
		}
	}
}

func TestBech32RoundTrip(t *testing.T) {
	// Test round-trip with various data sizes.
	testCases := []struct {
		hrp  string
		data []byte
	}{
		{"qc", make([]byte, 16)}, // 16 bytes (our fingerprint size)
		{"qc", []byte{0xff, 0x00, 0xaa, 0x55, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44}},
		{"test", []byte{1, 2, 3, 4, 5}},
		{"bc", []byte{0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22}},
	}

	for _, tc := range testCases {
		encoded, err := Bech32Encode(tc.hrp, tc.data)
		if err != nil {
			t.Errorf("Bech32Encode(%q, %x) failed: %v", tc.hrp, tc.data, err)
			continue
		}

		hrp, data, err := Bech32Decode(encoded)
		if err != nil {
			t.Errorf("Bech32Decode(%q) failed: %v", encoded, err)
			continue
		}

		if hrp != tc.hrp {
			t.Errorf("Round-trip HRP mismatch: got %q, want %q", hrp, tc.hrp)
		}
		if !bytes.Equal(data, tc.data) {
			t.Errorf("Round-trip data mismatch: got %x, want %x", data, tc.data)
		}
	}
}

func TestBech32CaseInsensitive(t *testing.T) {
	// Encoding should produce lowercase.
	encoded, err := Bech32Encode("QC", []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Bech32Encode failed: %v", err)
	}
	if encoded != strings.ToLower(encoded) {
		t.Errorf("Bech32Encode should produce lowercase, got %q", encoded)
	}

	// Decoding should accept both cases (but not mixed).
	upper := strings.ToUpper(encoded)
	hrp1, data1, err := Bech32Decode(encoded)
	if err != nil {
		t.Fatalf("Bech32Decode lowercase failed: %v", err)
	}
	hrp2, data2, err := Bech32Decode(upper)
	if err != nil {
		t.Fatalf("Bech32Decode uppercase failed: %v", err)
	}

	if hrp1 != hrp2 || !bytes.Equal(data1, data2) {
		t.Errorf("Case-insensitive decode mismatch")
	}
}

func TestBech32MixedCaseRejected(t *testing.T) {
	// Mixed case should be rejected.
	_, _, err := Bech32Decode("Qc1qpzry9")
	if err == nil {
		t.Error("Mixed case should be rejected")
	}
}

func TestBech32FingerprintSize(t *testing.T) {
	// Test that 16-byte fingerprint encodes to reasonable length.
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i * 17) // Some pattern
	}

	encoded, err := Bech32Encode("qc", data)
	if err != nil {
		t.Fatalf("Bech32Encode failed: %v", err)
	}

	// 16 bytes = 128 bits
	// 128 bits / 5 bits per char = 26 chars (rounded up)
	// + 6 char checksum + "qc1" prefix = 35 chars total
	t.Logf("16-byte fingerprint encodes to %d chars: %s", len(encoded), encoded)

	if len(encoded) > 40 {
		t.Errorf("Encoded fingerprint too long: %d chars", len(encoded))
	}
}

func TestFPBech32Integration(t *testing.T) {
	// Test the FP type with bech32 encoding.

	// Create a fingerprint from known bytes.
	var fp FP
	for i := range fp {
		fp[i] = byte(i + 1)
	}

	// String should return bech32.
	s := fp.String()
	if !strings.HasPrefix(s, "qc1") {
		t.Errorf("FP.String() should start with 'qc1', got %q", s)
	}
	t.Logf("FP.String() = %q (len=%d)", s, len(s))

	// ParseFP should round-trip.
	fp2, err := ParseFP(s)
	if err != nil {
		t.Fatalf("ParseFP(%q) failed: %v", s, err)
	}
	if fp != fp2 {
		t.Errorf("Round-trip failed: got %x, want %x", fp2, fp)
	}

	// Zero fingerprint.
	var zeroFP FP
	if !zeroFP.IsZero() {
		t.Error("Zero FP should be zero")
	}
	if fp.IsZero() {
		t.Error("Non-zero FP should not be zero")
	}

	// Empty string returns zero FP.
	emptyFP, err := ParseFP("")
	if err != nil {
		t.Errorf("ParseFP(\"\") failed: %v", err)
	}
	if !emptyFP.IsZero() {
		t.Error("ParseFP(\"\") should return zero FP")
	}

	// Invalid input should error.
	_, err = ParseFP("not-valid-bech32")
	if err == nil {
		t.Error("ParseFP should reject invalid input")
	}
}

func TestFPBech32CaseInsensitive(t *testing.T) {
	var fp FP
	for i := range fp {
		fp[i] = byte(i * 7)
	}

	s := fp.String()
	upper := strings.ToUpper(s)

	// Both should parse to the same FP.
	fp1, err := ParseFP(s)
	if err != nil {
		t.Fatalf("ParseFP(lower) failed: %v", err)
	}
	fp2, err := ParseFP(upper)
	if err != nil {
		t.Fatalf("ParseFP(upper) failed: %v", err)
	}

	if fp1 != fp2 {
		t.Errorf("Case sensitivity issue: %x != %x", fp1, fp2)
	}
}
