package qdef

import (
	"fmt"
	"strings"
)

// Bech32 encoding/decoding based on BIP-173.
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

const (
	// bech32Charset is the character set for bech32 encoding.
	// Excludes 1, b, i, o to avoid confusion.
	bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	// FPPrefix is the human-readable prefix for qconn fingerprints.
	FPPrefix = "qc"
)

var bech32CharsetRev = [128]int8{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
}

// bech32Polymod calculates the BCH checksum.
func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the human-readable part for checksum calculation.
func bech32HRPExpand(hrp string) []int {
	ret := make([]int, len(hrp)*2+1)
	for i, c := range hrp {
		ret[i] = int(c >> 5)
		ret[i+len(hrp)+1] = int(c & 31)
	}
	return ret
}

// bech32VerifyChecksum verifies the checksum of a bech32 string.
func bech32VerifyChecksum(hrp string, data []int) bool {
	values := append(bech32HRPExpand(hrp), data...)
	return bech32Polymod(values) == 1
}

// bech32CreateChecksum creates a checksum for the given HRP and data.
func bech32CreateChecksum(hrp string, data []int) []int {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	ret := make([]int, 6)
	for i := 0; i < 6; i++ {
		ret[i] = (polymod >> (5 * (5 - i))) & 31
	}
	return ret
}

// Bech32Encode encodes data with the given human-readable prefix.
// The HRP is always converted to lowercase per BIP-173.
func Bech32Encode(hrp string, data []byte) (string, error) {
	hrp = strings.ToLower(hrp)

	// Convert 8-bit data to 5-bit groups.
	conv, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Create checksum.
	checksum := bech32CreateChecksum(hrp, conv)
	combined := append(conv, checksum...)

	// Build result string.
	var result strings.Builder
	result.WriteString(hrp)
	result.WriteByte('1')
	for _, d := range combined {
		result.WriteByte(bech32Charset[d])
	}

	return result.String(), nil
}

// Bech32Decode decodes a bech32 string into HRP and data.
func Bech32Decode(s string) (string, []byte, error) {
	// Check for minimum length (HRP + separator + 6-char checksum).
	if len(s) < 8 {
		return "", nil, Bech32Error{Msg: "invalid length"}
	}

	// Check for invalid characters and mixed case.
	hasLower := false
	hasUpper := false
	for _, c := range s {
		if c < 33 || c > 126 {
			return "", nil, Bech32Error{Msg: "invalid character"}
		}
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return "", nil, Bech32Error{Msg: "mixed case"}
	}

	// Convert to lowercase for processing.
	s = strings.ToLower(s)

	// Find separator (last occurrence of '1').
	sepPos := strings.LastIndexByte(s, '1')
	if sepPos < 1 {
		return "", nil, Bech32Error{Msg: "no separator"}
	}
	if sepPos+7 > len(s) {
		return "", nil, Bech32Error{Msg: "too short"}
	}

	hrp := s[:sepPos]
	dataStr := s[sepPos+1:]

	// Decode data part.
	data := make([]int, len(dataStr))
	for i, c := range dataStr {
		if c >= 128 || bech32CharsetRev[c] == -1 {
			return "", nil, Bech32Error{Msg: fmt.Sprintf("invalid character: %c", c)}
		}
		data[i] = int(bech32CharsetRev[c])
	}

	// Verify checksum.
	if !bech32VerifyChecksum(hrp, data) {
		return "", nil, Bech32Error{Msg: "invalid checksum, typo?"}
	}

	// Remove checksum and convert back to 8-bit.
	conv, err := convertBits(intSliceToBytes(data[:len(data)-6]), 5, 8, false)
	if err != nil {
		return "", nil, err
	}

	return hrp, intSliceToBytes(conv), nil
}

// convertBits converts between bit groups.
func convertBits(data []byte, fromBits, toBits int, pad bool) ([]int, error) {
	acc := 0
	bits := 0
	var ret []int
	maxv := (1 << toBits) - 1

	for _, value := range data {
		if int(value)>>fromBits != 0 {
			return nil, Bech32Error{Msg: "invalid data range"}
		}
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}

	if pad {
		if bits > 0 {
			ret = append(ret, (acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits {
		return nil, Bech32Error{Msg: "invalid padding"}
	} else if (acc<<(toBits-bits))&maxv != 0 {
		return nil, Bech32Error{Msg: "non-zero padding"}
	}

	return ret, nil
}

func intSliceToBytes(data []int) []byte {
	ret := make([]byte, len(data))
	for i, v := range data {
		ret[i] = byte(v)
	}
	return ret
}

// Bech32Error represents a bech32 encoding/decoding error.
type Bech32Error struct {
	Msg string
}

func (e Bech32Error) Error() string {
	return "bech32: " + e.Msg
}
