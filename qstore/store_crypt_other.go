//go:build !windows

package qstore

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

// Embedded key for encryption. This provides obfuscation rather than
// strong security since anyone with access to the binary can extract it.
// The goal is to keep credentials out of plain text.
var embeddedKey = [32]byte{
	0x7a, 0x3f, 0x9c, 0x2b, 0x8e, 0x1d, 0x4a, 0x6f,
	0xb5, 0x82, 0xd9, 0x0c, 0x73, 0xe4, 0x51, 0xa8,
	0x2f, 0x96, 0x4b, 0xc3, 0x18, 0x7d, 0xe6, 0x5a,
	0x09, 0xf1, 0x64, 0xbd, 0x3e, 0x87, 0xc0, 0x25,
}

// encryptValue encrypts data using nacl/secretbox with the embedded key.
// Returns nonce (24 bytes) + ciphertext.
func encryptValue(plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := secretbox.Seal(nonce[:], plaintext, &nonce, &embeddedKey)
	return ciphertext, nil
}

// decryptValue decrypts data encrypted with Encrypt.
// Expects nonce (24 bytes) + ciphertext.
func decryptValue(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24+secretbox.Overhead {
		return nil, fmt.Errorf("ciphertext too short")
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	plaintext, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &embeddedKey)
	if !ok {
		return nil, fmt.Errorf("decrypt failed")
	}

	return plaintext, nil
}
