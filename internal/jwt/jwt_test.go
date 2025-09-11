package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func TestCreateJWT(t *testing.T) {
	// generate test key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	kid := "test-key-id"
	issuer := "test-issuer"
	expiry := 5 * time.Minute

	token, err := CreateJWT(privKey, kid, issuer, expiry)
	if err != nil {
		t.Fatalf("CreateJWT() error = %v", err)
	}

	if token == "" {
		t.Error("CreateJWT() returned empty token")
	}

	// JWT should have 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("Expected JWT to have 3 parts, got %d", len(parts))
	}

	// each part should be non-empty
	for i, part := range parts {
		if part == "" {
			t.Errorf("JWT part %d is empty", i)
		}
	}
}

func TestSignRS256(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	data := []byte("test message")
	signature, err := signRS256(data, privKey)
	if err != nil {
		t.Fatalf("signRS256() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("signRS256() returned empty signature")
	}

	// signature should be 256 bytes for 2048-bit key
	if len(signature) != 256 {
		t.Errorf("Expected signature length 256, got %d", len(signature))
	}
}

func TestEncodeBase64URL(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello"), "aGVsbG8"},
		{[]byte("test"), "dGVzdA"},
		{[]byte(""), ""},
		{[]byte("a"), "YQ"},
		{[]byte("ab"), "YWI"},
		{[]byte("abc"), "YWJj"},
	}

	for _, test := range tests {
		result := encodeBase64URL(test.input)
		if result != test.expected {
			t.Errorf("encodeBase64URL(%q) = %q, want %q", test.input, result, test.expected)
		}
	}
}

func TestJWTStructure(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	kid := "test-key-123"
	issuer := "jwt-test-issuer"
	expiry := 10 * time.Minute

	token, err := CreateJWT(privKey, kid, issuer, expiry)
	if err != nil {
		t.Fatalf("CreateJWT() error = %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected 3 JWT parts, got %d", len(parts))
	}

	// test that parts are base64url encoded (no padding, use - and _)
	for i, part := range parts {
		if strings.Contains(part, "+") || strings.Contains(part, "/") || strings.Contains(part, "=") {
			t.Errorf("JWT part %d contains standard base64 characters instead of base64url", i)
		}
	}
}

func TestMultipleJWTsAreDifferent(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	kid1 := "test-key-1"
	kid2 := "test-key-2"
	issuer := "test-issuer"
	expiry := 5 * time.Minute

	token1, err := CreateJWT(privKey, kid1, issuer, expiry)
	if err != nil {
		t.Fatalf("CreateJWT() error = %v", err)
	}

	token2, err := CreateJWT(privKey, kid2, issuer, expiry)
	if err != nil {
		t.Fatalf("CreateJWT() error = %v", err)
	}

	if token1 == token2 {
		t.Error("JWTs with different kids should be different")
	}
}

func TestJWTWithDifferentKeys(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key 1: %v", err)
	}

	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key 2: %v", err)
	}

	kid1 := "key-1"
	kid2 := "key-2"
	issuer := "test-issuer"
	expiry := 5 * time.Minute

	token1, err := CreateJWT(privKey1, kid1, issuer, expiry)
	if err != nil {
		t.Fatalf("CreateJWT() with key 1 error = %v", err)
	}

	token2, err := CreateJWT(privKey2, kid2, issuer, expiry)
	if err != nil {
		t.Fatalf("CreateJWT() with key 2 error = %v", err)
	}

	if token1 == token2 {
		t.Error("JWTs signed with different keys should be different")
	}
}
