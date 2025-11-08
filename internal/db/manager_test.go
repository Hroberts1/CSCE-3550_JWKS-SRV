package db

import (
	"crypto/rsa"
	"path/filepath"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_encrypted.db")
	encryptionKey := "test-encryption-key-123"

	manager, err := NewManager(dbPath, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.database.Close()

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	if manager.database == nil {
		t.Fatal("Manager database is nil")
	}

	if manager.encryptor == nil {
		t.Fatal("Manager encryptor is nil")
	}
}

func TestManagerStoreAndRetrieveKey(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_encrypted.db")
	encryptionKey := "test-encryption-key-123"

	manager, err := NewManager(dbPath, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.database.Close()

	// generate test key
	privateKey, err := generateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// store encrypted key
	expiry := time.Now().Add(time.Hour)
	kid, err := manager.StoreKey(privateKey, expiry)
	if err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	if kid == 0 {
		t.Fatal("StoreKey() returned zero kid")
	}

	// retrieve valid keys
	validKeys, err := manager.GetValidKeys()
	if err != nil {
		t.Fatalf("GetValidKeys() error = %v", err)
	}

	if len(validKeys) == 0 {
		t.Fatal("No valid keys found")
	}

	retrievedKey, exists := validKeys[kid]
	if !exists {
		t.Fatal("Stored key not found in valid keys")
	}

	// verify key integrity
	if privateKey.N.Cmp(retrievedKey.N) != 0 {
		t.Error("Retrieved key modulus doesn't match original")
	}

	if privateKey.E != retrievedKey.E {
		t.Error("Retrieved key exponent doesn't match original")
	}
}

func TestManagerGetExpiredKeys(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_encrypted.db")
	encryptionKey := "test-encryption-key-123"

	manager, err := NewManager(dbPath, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.database.Close()

	// store expired key
	privateKey, err := generateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	expiry := time.Now().Add(-time.Hour) // expired 1 hour ago
	kid, err := manager.StoreKey(privateKey, expiry)
	if err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	// retrieve expired keys
	expiredKeys, err := manager.GetExpiredKeys()
	if err != nil {
		t.Fatalf("GetExpiredKeys() error = %v", err)
	}

	if len(expiredKeys) == 0 {
		t.Fatal("No expired keys found")
	}

	retrievedKey, exists := expiredKeys[kid]
	if !exists {
		t.Fatal("Stored expired key not found")
	}

	// verify key integrity
	if privateKey.N.Cmp(retrievedKey.N) != 0 {
		t.Error("Retrieved expired key modulus doesn't match original")
	}
}

func TestEncryptionKeyMismatch(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_mismatch.db")

	// store with one key
	manager1, err := NewManager(dbPath, "key1")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	privateKey, _ := generateRSAKey(2048)
	_, err = manager1.StoreKey(privateKey, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}
	manager1.database.Close()

	// try to retrieve with different key
	manager2, err := NewManager(dbPath, "key2")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager2.database.Close()

	// should fail to decrypt
	_, err = manager2.GetValidKeys()
	if err == nil {
		t.Error("Expected error when using wrong encryption key")
	}
}

func TestEmptyDatabase(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_empty.db")
	encryptionKey := "test-encryption-key-123"

	manager, err := NewManager(dbPath, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.database.Close()

	// test getting keys from empty database
	validKeys, err := manager.GetValidKeys()
	if err != nil {
		t.Fatalf("GetValidKeys() error = %v", err)
	}

	if len(validKeys) != 0 {
		t.Errorf("Expected 0 keys from empty database, got %d", len(validKeys))
	}

	expiredKeys, err := manager.GetExpiredKeys()
	if err != nil {
		t.Fatalf("GetExpiredKeys() error = %v", err)
	}

	if len(expiredKeys) != 0 {
		t.Errorf("Expected 0 expired keys from empty database, got %d", len(expiredKeys))
	}
}

func TestInvalidEncryptionKey(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_invalid.db")

	// test with empty encryption key
	manager, err := NewManager(dbPath, "")
	if err == nil {
		t.Error("NewManager() should fail with empty encryption key")
		if manager != nil && manager.database != nil {
			manager.database.Close()
		}
	}
}

func TestMultipleKeys(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_multiple.db")
	encryptionKey := "test-encryption-key-123"

	manager, err := NewManager(dbPath, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.database.Close()

	// store multiple keys
	numKeys := 5
	originalKeys := make([]*rsa.PrivateKey, numKeys)
	kids := make([]int, numKeys)

	for i := 0; i < numKeys; i++ {
		privateKey, err := generateRSAKey(2048)
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}

		expiry := time.Now().Add(time.Hour)
		kid, err := manager.StoreKey(privateKey, expiry)
		if err != nil {
			t.Fatalf("StoreKey() %d error = %v", i, err)
		}

		originalKeys[i] = privateKey
		kids[i] = kid
	}

	// retrieve all keys
	validKeys, err := manager.GetValidKeys()
	if err != nil {
		t.Fatalf("GetValidKeys() error = %v", err)
	}

	if len(validKeys) != numKeys {
		t.Fatalf("Expected %d keys, got %d", numKeys, len(validKeys))
	}

	// verify all keys are present and correct
	for i, kid := range kids {
		retrievedKey, exists := validKeys[kid]
		if !exists {
			t.Errorf("Key %d (kid %d) not found", i, kid)
			continue
		}

		if originalKeys[i].N.Cmp(retrievedKey.N) != 0 {
			t.Errorf("Key %d modulus doesn't match", i)
		}
	}
}

func TestLargeKeyData(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_large.db")
	encryptionKey := "test-encryption-key-123"

	manager, err := NewManager(dbPath, encryptionKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.database.Close()

	// test with larger key size
	privateKey, err := generateRSAKey(4096) // larger key
	if err != nil {
		t.Fatalf("Failed to generate large key: %v", err)
	}

	expiry := time.Now().Add(time.Hour)
	kid, err := manager.StoreKey(privateKey, expiry)
	if err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	// retrieve and verify
	validKeys, err := manager.GetValidKeys()
	if err != nil {
		t.Fatalf("GetValidKeys() error = %v", err)
	}

	retrievedKey, exists := validKeys[kid]
	if !exists {
		t.Fatal("Large key not found")
	}

	if privateKey.N.Cmp(retrievedKey.N) != 0 {
		t.Error("Large key modulus doesn't match")
	}
}
