package keys

import (
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	keyLifetime := 10 * time.Minute
	keyRetainPeriod := time.Hour
	encryptionKey := "test-encryption-key-123"

	manager, err := NewManager(keyLifetime, keyRetainPeriod, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}

	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	if manager.keyLifetime != keyLifetime {
		t.Errorf("Expected keyLifetime to be %v, got %v", keyLifetime, manager.keyLifetime)
	}

	if manager.keyRetainPeriod != keyRetainPeriod {
		t.Errorf("Expected keyRetainPeriod to be %v, got %v", keyRetainPeriod, manager.keyRetainPeriod)
	}

	if manager.keys == nil {
		t.Error("Keys map not initialized")
	}

	if manager.stopCh == nil {
		t.Error("Stop channel not initialized")
	}
}

func TestManagerStart(t *testing.T) {
	manager, err := NewManager(time.Minute, time.Hour, "test-encryption-key-123")
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}

	// start should generate initial key
	manager.Start()
	defer manager.Stop()

	// give it time to generate key
	time.Sleep(100 * time.Millisecond)

	if manager.currentKey == nil {
		t.Error("Current key not set after start")
	}

	if len(manager.keys) == 0 {
		t.Error("No keys in manager after start")
	}
}

func TestManagerGetValidKeys(t *testing.T) {
	manager, err := NewManager(time.Minute, time.Hour, "test-encryption-key-123")
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	manager.Start()
	defer manager.Stop()

	// give it time to generate key
	time.Sleep(100 * time.Millisecond)

	validKeys := manager.GetValidKeys()

	if len(validKeys) == 0 {
		t.Error("No valid keys returned")
	}

	// all returned keys should be valid
	now := time.Now()
	for _, key := range validKeys {
		if key.IsExpired(now) {
			t.Error("Expired key returned in valid keys")
		}
	}
}

func TestManagerGetSigningKey(t *testing.T) {
	manager, err := NewManager(time.Minute, time.Hour, "test-encryption-key-123")
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	manager.Start()
	defer manager.Stop()

	// give it time to generate key
	time.Sleep(100 * time.Millisecond)

	// test getting valid signing key from database
	signingKey := manager.GetSigningKey(false)
	if signingKey == nil {
		t.Error("No signing key returned")
		return
	}

	// verify the key has a valid ID from database
	if signingKey.ID == "" {
		t.Error("Signing key should have a valid ID from database")
	}

	// test getting expired key (should return nil if no expired keys exist)
	expiredKey := manager.GetSigningKey(true)
	// Note: expiredKey might be nil if no expired keys exist yet, which is correct behavior
	if expiredKey != nil {
		// if we got an expired key, verify it has an ID
		if expiredKey.ID == "" {
			t.Error("Expired key should have a valid ID from database")
		}
	}
}

func TestManagerGetJWKS(t *testing.T) {
	manager, err := NewManager(time.Minute, time.Hour, "test-encryption-key-123")
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	manager.Start()
	defer manager.Stop()

	// give it time to generate key
	time.Sleep(100 * time.Millisecond)

	jwks, err := manager.GetJWKS()
	if err != nil {
		t.Fatalf("GetJWKS() error = %v", err)
	}

	if jwks == nil {
		t.Fatal("GetJWKS() returned nil")
	}

	if len(jwks.Keys) == 0 {
		t.Error("No keys in JWKS")
	}

	// test JWKS structure
	for _, key := range jwks.Keys {
		if key["kty"] != "RSA" {
			t.Error("Invalid key type in JWKS")
		}

		if key["kid"] == nil {
			t.Error("Missing kid in JWKS key")
		}
	}
}

func TestManagerRotateKey(t *testing.T) {
	manager, err := NewManager(time.Minute, time.Hour, "test-encryption-key-123")
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}

	// manually rotate key to test
	err = manager.rotateKey()
	if err != nil {
		t.Fatalf("rotateKey() error = %v", err)
	}

	if manager.currentKey == nil {
		t.Error("Current key not set after rotation")
	}

	oldKey := manager.currentKey

	// rotate again
	err = manager.rotateKey()
	if err != nil {
		t.Fatalf("Second rotateKey() error = %v", err)
	}

	if manager.currentKey == oldKey {
		t.Error("Current key not updated after rotation")
	}

	// should have both keys
	if len(manager.keys) != 2 {
		t.Errorf("Expected 2 keys after rotation, got %d", len(manager.keys))
	}
}

func TestManagerCleanup(t *testing.T) {
	manager, err := NewManager(time.Minute, time.Millisecond, "test-encryption-key-123") // very short retain period
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}

	// add an old expired key manually
	oldKey := &Key{
		ID:        "old-key",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	manager.keys[oldKey.ID] = oldKey

	// add current key
	manager.rotateKey()

	initialCount := len(manager.keys)

	// run cleanup
	time.Sleep(2 * time.Millisecond) // wait for retain period
	manager.cleanup()

	// old key should be removed
	if len(manager.keys) >= initialCount {
		t.Error("Cleanup did not remove old keys")
	}

	if _, exists := manager.keys[oldKey.ID]; exists {
		t.Error("Old expired key still exists after cleanup")
	}
}

func TestManagerStop(t *testing.T) {
	manager, err := NewManager(time.Minute, time.Hour, "test-encryption-key-123")
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	manager.Start()

	// stop should not panic
	manager.Stop()

	// stopping again should not panic
	manager.Stop()
}
