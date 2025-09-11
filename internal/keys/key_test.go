package keys

import (
	"testing"
	"time"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	key, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() error = %v", err)
	}

	if key == nil {
		t.Fatal("GenerateRSAKeyPair() returned nil key")
	}

	if key.ID == "" {
		t.Error("Key ID is empty")
	}

	if key.PrivateKey == nil {
		t.Error("Private key is nil")
	}

	if key.PublicKey == nil {
		t.Error("Public key is nil")
	}

	if key.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	if key.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}

	// test key size
	if key.PrivateKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d-bit", key.PrivateKey.N.BitLen())
	}
}

func TestGenerateKID(t *testing.T) {
	kid1 := generateKID()
	time.Sleep(time.Nanosecond) // ensure different timestamps
	kid2 := generateKID()

	if kid1 == "" {
		t.Error("generateKID() returned empty string")
	}

	if kid2 == "" {
		t.Error("generateKID() returned empty string")
	}

	if kid1 == kid2 {
		t.Error("generateKID() returned duplicate IDs")
	}

	// test format
	if len(kid1) < 5 {
		t.Error("generateKID() returned too short ID")
	}
}

func TestKeyIsExpired(t *testing.T) {
	now := time.Now()

	// not expired key
	key := &Key{
		ID:        "test-key",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}

	if key.IsExpired(now) {
		t.Error("Key should not be expired")
	}

	// expired key
	expiredKey := &Key{
		ID:        "expired-key",
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}

	if !expiredKey.IsExpired(now) {
		t.Error("Key should be expired")
	}
}

func TestKeyToJWK(t *testing.T) {
	key, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() error = %v", err)
	}

	jwk := key.ToJWK()

	// test required fields
	if jwk["kty"] != "RSA" {
		t.Errorf("Expected kty to be 'RSA', got %v", jwk["kty"])
	}

	if jwk["use"] != "sig" {
		t.Errorf("Expected use to be 'sig', got %v", jwk["use"])
	}

	if jwk["kid"] != key.ID {
		t.Errorf("Expected kid to be %v, got %v", key.ID, jwk["kid"])
	}

	if jwk["alg"] != "RS256" {
		t.Errorf("Expected alg to be 'RS256', got %v", jwk["alg"])
	}

	// test modulus and exponent
	if jwk["n"] == nil {
		t.Error("Modulus 'n' is missing")
	}

	if jwk["e"] == nil {
		t.Error("Exponent 'e' is missing")
	}
}

func TestIntToBytes(t *testing.T) {
	tests := []struct {
		input    int
		expected []byte
	}{
		{65537, []byte{1, 0, 1}},
		{3, []byte{3}},
		{256, []byte{1, 0}},
	}

	for _, test := range tests {
		result := intToBytes(test.input)
		if len(result) != len(test.expected) {
			t.Errorf("intToBytes(%d) length = %d, want %d", test.input, len(result), len(test.expected))
			continue
		}

		for i, b := range result {
			if b != test.expected[i] {
				t.Errorf("intToBytes(%d)[%d] = %d, want %d", test.input, i, b, test.expected[i])
			}
		}
	}
}

func TestEncodeBase64URL(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello"), "aGVsbG8"},
		{[]byte("test"), "dGVzdA"},
		{[]byte{1, 0, 1}, "AQAB"},
	}

	for _, test := range tests {
		result := encodeBase64URL(test.input)
		if result != test.expected {
			t.Errorf("encodeBase64URL(%v) = %s, want %s", test.input, result, test.expected)
		}
	}
}
