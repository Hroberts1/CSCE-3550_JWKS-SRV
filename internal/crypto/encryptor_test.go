package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewEncryptor(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		wantErr    error
	}{
		{
			name:       "valid passphrase",
			passphrase: "test-passphrase-123",
			wantErr:    nil,
		},
		{
			name:       "empty passphrase",
			passphrase: "",
			wantErr:    ErrEmptyPassphrase,
		},
		{
			name:       "unicode passphrase",
			passphrase: "测试密码🔐",
			wantErr:    nil,
		},
		{
			name:       "long passphrase",
			passphrase: "this-is-a-very-long-passphrase-that-should-work-fine-even-though-it-is-much-longer-than-typical",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptor, err := NewEncryptor(tt.passphrase)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NewEncryptor() error = %v, wantErr %v", err, tt.wantErr)
				}
				if encryptor != nil {
					t.Error("NewEncryptor() should return nil encryptor on error")
				}
				return
			}

			if err != nil {
				t.Errorf("NewEncryptor() unexpected error = %v", err)
				return
			}

			if encryptor == nil {
				t.Error("NewEncryptor() returned nil encryptor")
				return
			}

			if encryptor.aead == nil {
				t.Error("NewEncryptor() returned encryptor with nil AEAD")
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		plaintext  []byte
	}{
		{
			name:       "simple text",
			passphrase: "test-passphrase-123",
			plaintext:  []byte("Hello, World!"),
		},
		{
			name:       "pem data",
			passphrase: "my-secret-key",
			plaintext:  []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."),
		},
		{
			name:       "empty data",
			passphrase: "another-key",
			plaintext:  []byte(""),
		},
		{
			name:       "binary data",
			passphrase: "binary-key",
			plaintext:  []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name:       "large data",
			passphrase: "large-data-key",
			plaintext:  make([]byte, 1000), // 1KB of zeros
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptor, err := NewEncryptor(tt.passphrase)
			if err != nil {
				t.Fatalf("NewEncryptor() error = %v", err)
			}

			// encrypt
			ciphertext, err := encryptor.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// verify ciphertext is different from plaintext (unless both are empty)
			if len(tt.plaintext) > 0 && bytes.Equal(ciphertext, tt.plaintext) {
				t.Error("Ciphertext should not equal plaintext for non-empty data")
			}

			// verify ciphertext is longer than plaintext (due to nonce + auth tag)
			expectedMinLength := len(tt.plaintext) + encryptor.aead.NonceSize() + encryptor.aead.Overhead()
			if len(ciphertext) < expectedMinLength {
				t.Errorf("Ciphertext length %d should be at least %d", len(ciphertext), expectedMinLength)
			}

			// decrypt
			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// verify decrypted matches original
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypted data doesn't match original.\nGot:  %x\nWant: %x", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptionDeterminism(t *testing.T) {
	encryptor, err := NewEncryptor("test-key")
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := []byte("test data")

	// encrypt same data multiple times
	ciphertext1, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	ciphertext2, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// ciphertexts should be different due to random nonces
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Multiple encryptions of same data should produce different ciphertexts")
	}

	// but both should decrypt to same plaintext
	decrypted1, err := encryptor.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	decrypted2, err := encryptor.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("Both ciphertexts should decrypt to original plaintext")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	encryptor, err := NewEncryptor("test-key")
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    error
	}{
		{
			name:       "too short",
			ciphertext: []byte("short"),
			wantErr:    ErrCiphertextTooShort,
		},
		{
			name:       "empty data",
			ciphertext: []byte{},
			wantErr:    ErrCiphertextTooShort,
		},
		{
			name:       "invalid but correct length",
			ciphertext: make([]byte, 32), // correct length but random data
			wantErr:    nil,              // should return wrapped error from AEAD.Open
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.Decrypt(tt.ciphertext)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				// for invalid but correct length data, we expect some error
				if err == nil {
					t.Error("Decrypt() should return error for invalid ciphertext")
				}
			}
		})
	}
}

func TestDifferentPassphrases(t *testing.T) {
	plaintext := []byte("secret data")

	encryptor1, err := NewEncryptor("passphrase1")
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	encryptor2, err := NewEncryptor("passphrase2")
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	// encrypt with first encryptor
	ciphertext, err := encryptor1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// try to decrypt with second encryptor (should fail)
	_, err = encryptor2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt() should fail when using wrong passphrase")
	}

	// verify first encryptor can still decrypt
	decrypted, err := encryptor1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() with correct passphrase should succeed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data should match original")
	}
}
