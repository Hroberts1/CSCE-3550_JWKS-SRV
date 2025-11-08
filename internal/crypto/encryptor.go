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

// Encrypt encrypts plaintext data using AES-GCM with a randomly generated nonce.
// The nonce is prepended to the ciphertext for retrieval during decryption.
// Returns an error if random nonce generation fails.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		// allow encrypting empty data
		plaintext = []byte{}
	}

	// generate random nonce
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// encrypt and authenticate data, prepending nonce to ciphertext
	ciphertext := e.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext data using AES-GCM.
// The nonce is expected to be prepended to the ciphertext.
// Returns ErrCiphertextTooShort if the ciphertext is too short to contain a valid nonce.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	// extract nonce and encrypted data
	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	// decrypt and authenticate data
	plaintext, err := e.aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}
