package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

var (
	// ErrCiphertextTooShort indicates the provided ciphertext is shorter than the minimum required length
	ErrCiphertextTooShort = fmt.Errorf("ciphertext too short to contain valid nonce")

	// ErrEmptyPassphrase indicates an empty passphrase was provided for key derivation
	ErrEmptyPassphrase = fmt.Errorf("passphrase cannot be empty")
)

// Encryptor provides AES-GCM encryption and decryption for RSA private keys.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor creates a new AES-GCM encryptor from a passphrase.
func NewEncryptor(passphrase string) (*Encryptor, error) {
	if passphrase == "" {
		return nil, ErrEmptyPassphrase
	}

	// derive 32-byte key from passphrase using SHA256
	keyHash := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	return &Encryptor{aead: aead}, nil
}

