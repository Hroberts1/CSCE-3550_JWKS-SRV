package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"
)

// gen RSA key pair w/ metadata
func GenerateRSAKeyPair() (*Key, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	now := time.Now()
	keyID := generateKID()

	return &Key{
		ID:         keyID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute), // default 10min expiry
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
	}, nil
}

// gen unique key ID
func generateKID() string {
	return fmt.Sprintf("key-%d", time.Now().UnixNano())
}
