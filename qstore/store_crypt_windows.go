//go:build windows

package qstore

import (
	"github.com/billgraziano/dpapi"
)

// encryptValue encrypts data using Windows DPAPI.
func encryptValue(plaintext []byte) ([]byte, error) {
	return dpapi.EncryptBytes(plaintext)
}

// decryptValue decrypts data encrypted with Encrypt using Windows DPAPI.
func decryptValue(ciphertext []byte) ([]byte, error) {
	return dpapi.DecryptBytes(ciphertext)
}
