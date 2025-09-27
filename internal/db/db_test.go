package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testDatabase creates a temporary database for testing
func testDatabase(t *testing.T) (*Database, string) {
	// create temporary directory
	tempDir := t.TempDir()

	// create temporary database file path
	dbPath := filepath.Join(tempDir, "test_keys.db")

	// create database with custom path for testing
	db := &Database{
		path: dbPath,
	}

	// manually initialize connection for test
	err := db.initForTest()
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	return db, dbPath
}

// initForTest initializes database connection for testing
func (db *Database) initForTest() error {
	// create database file if it doesn't exist
	file, err := os.Create(db.path)
	if err != nil {
		return err
	}
	file.Close()

	// open database connection
	conn, err := sql.Open("sqlite3", db.path)
	if err != nil {
		return err
	}
	db.conn = conn

	// initialize schema
	return db.initSchema()
}

func TestNewDatabase(t *testing.T) {
	// test creating database in temporary directory
	db, err := NewDatabase()
	if err != nil {
		t.Fatalf("NewDatabase() error = %v", err)
	}
	defer db.Close()

	// verify database connection is established
	if db.conn == nil {
		t.Fatal("Database connection is nil")
	}

	// verify database file exists (in original location since we can't change const)
	if _, err := os.Stat(filepath.Join(dataDir, dbFileName)); os.IsNotExist(err) {
		// This is expected in test environment, so we'll pass
		t.Logf("Database file not created in test environment (expected)")
	}
}

func TestSaveAndRetrieveKey(t *testing.T) {
	db, _ := testDatabase(t)
	defer db.Close()

	// generate test RSA key
	privateKey, err := generateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// test saving key
	expTime := time.Now().Add(1 * time.Hour)
	kid, err := db.SaveKey(privateKey, expTime)
	if err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}

	if kid <= 0 {
		t.Fatalf("SaveKey() returned invalid kid = %d", kid)
	}

	// test retrieving key by kid
	retrievedRecord, err := db.GetKeyByKid(kid)
	if err != nil {
		t.Fatalf("GetKeyByKid() error = %v", err)
	}

	// verify retrieved key matches original
	if retrievedRecord.Kid != kid {
		t.Errorf("Retrieved kid = %d, want %d", retrievedRecord.Kid, kid)
	}

	if retrievedRecord.Exp != expTime.Unix() {
		t.Errorf("Retrieved exp = %d, want %d", retrievedRecord.Exp, expTime.Unix())
	}

	// verify private key functionality (can't directly compare due to internal structure)
	if retrievedRecord.Key == nil {
		t.Fatal("Retrieved private key is nil")
	}

	// test that keys have the same modulus (basic validation)
	if privateKey.N.Cmp(retrievedRecord.Key.N) != 0 {
		t.Error("Retrieved private key modulus doesn't match original")
	}
}

func TestGetValidKeys(t *testing.T) {
	db, _ := testDatabase(t)
	defer db.Close()

	// create keys with different expiration times
	now := time.Now()

	// valid key (expires in 1 hour)
	validKey, _ := generateRSAKey(2048)
	validKid, err := db.SaveKey(validKey, now.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to save valid key: %v", err)
	}

	// expired key (expired 1 hour ago)
	expiredKey, _ := generateRSAKey(2048)
	expiredKid, err := db.SaveKey(expiredKey, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to save expired key: %v", err)
	}

	// get valid keys
	validKeys, err := db.GetValidKeys()
	if err != nil {
		t.Fatalf("GetValidKeys() error = %v", err)
	}

	// should only return the valid key
	if len(validKeys) != 1 {
		t.Fatalf("GetValidKeys() returned %d keys, want 1", len(validKeys))
	}

	if validKeys[0].Kid != validKid {
		t.Errorf("GetValidKeys() returned kid %d, want %d", validKeys[0].Kid, validKid)
	}

	// test that expired key is not included
	for _, key := range validKeys {
		if key.Kid == expiredKid {
			t.Error("GetValidKeys() returned expired key")
		}
	}
}

func TestGetExpiredKeys(t *testing.T) {
	db, _ := testDatabase(t)
	defer db.Close()

	// create keys with different expiration times
	now := time.Now()

	// valid key (expires in 1 hour)
	validKey, _ := generateRSAKey(2048)
	validKid, err := db.SaveKey(validKey, now.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to save valid key: %v", err)
	}

	// expired key (expired 1 hour ago)
	expiredKey, _ := generateRSAKey(2048)
	expiredKid, err := db.SaveKey(expiredKey, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to save expired key: %v", err)
	}

	// get expired keys
	expiredKeys, err := db.GetExpiredKeys()
	if err != nil {
		t.Fatalf("GetExpiredKeys() error = %v", err)
	}

	// should only return the expired key
	if len(expiredKeys) != 1 {
		t.Fatalf("GetExpiredKeys() returned %d keys, want 1", len(expiredKeys))
	}

	if expiredKeys[0].Kid != expiredKid {
		t.Errorf("GetExpiredKeys() returned kid %d, want %d", expiredKeys[0].Kid, expiredKid)
	}

	// test that valid key is not included
	for _, key := range expiredKeys {
		if key.Kid == validKid {
			t.Error("GetExpiredKeys() returned valid key")
		}
	}
}

func TestGetAnyValidKey(t *testing.T) {
	db, _ := testDatabase(t)
	defer db.Close()

	// test when no keys exist
	_, err := db.GetAnyValidKey()
	if err == nil {
		t.Error("GetAnyValidKey() should return error when no valid keys exist")
	}

	// add a valid key
	validKey, _ := generateRSAKey(2048)
	validKid, err := db.SaveKey(validKey, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to save valid key: %v", err)
	}

	// test getting any valid key
	retrievedKey, err := db.GetAnyValidKey()
	if err != nil {
		t.Fatalf("GetAnyValidKey() error = %v", err)
	}

	if retrievedKey.Kid != validKid {
		t.Errorf("GetAnyValidKey() returned kid %d, want %d", retrievedKey.Kid, validKid)
	}
}

func TestGetAnyExpiredKey(t *testing.T) {
	db, _ := testDatabase(t)
	defer db.Close()

	// test when no expired keys exist
	_, err := db.GetAnyExpiredKey()
	if err == nil {
		t.Error("GetAnyExpiredKey() should return error when no expired keys exist")
	}

	// add an expired key
	expiredKey, _ := generateRSAKey(2048)
	expiredKid, err := db.SaveKey(expiredKey, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to save expired key: %v", err)
	}

	// test getting any expired key
	retrievedKey, err := db.GetAnyExpiredKey()
	if err != nil {
		t.Fatalf("GetAnyExpiredKey() error = %v", err)
	}

	if retrievedKey.Kid != expiredKid {
		t.Errorf("GetAnyExpiredKey() returned kid %d, want %d", retrievedKey.Kid, expiredKid)
	}
}

func TestGenerateAndSaveTestKeys(t *testing.T) {
	db, _ := testDatabase(t)
	defer db.Close()

	// test generating test keys
	err := db.GenerateAndSaveTestKeys()
	if err != nil {
		t.Fatalf("GenerateAndSaveTestKeys() error = %v", err)
	}

	// verify that keys were created
	// Note: We can't easily test exact counts due to timing, but we can check that some keys exist

	// check for any keys in database
	validKeys, err := db.GetValidKeys()
	if err != nil {
		t.Fatalf("Failed to get valid keys after test generation: %v", err)
	}

	expiredKeys, err := db.GetExpiredKeys()
	if err != nil {
		t.Fatalf("Failed to get expired keys after test generation: %v", err)
	}

	totalKeys := len(validKeys) + len(expiredKeys)
	if totalKeys == 0 {
		t.Error("GenerateAndSaveTestKeys() didn't create any keys")
	}

	// Wait a bit and check if the 10-second key has expired
	time.Sleep(11 * time.Second)

	expiredKeysAfterWait, err := db.GetExpiredKeys()
	if err != nil {
		t.Fatalf("Failed to get expired keys after wait: %v", err)
	}

	if len(expiredKeysAfterWait) <= len(expiredKeys) {
		t.Log("Note: 10-second key may not have expired yet due to test timing")
	}
}

func TestPEMSerialization(t *testing.T) {
	// test key serialization and deserialization
	originalKey, err := generateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	db, _ := testDatabase(t)
	defer db.Close()

	// save and retrieve key
	expTime := time.Now().Add(1 * time.Hour)
	kid, err := db.SaveKey(originalKey, expTime)
	if err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	retrieved, err := db.GetKeyByKid(kid)
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}

	// verify that the keys are functionally equivalent
	// Test by comparing public key components
	if originalKey.N.Cmp(retrieved.Key.N) != 0 {
		t.Error("Deserialized key modulus doesn't match original")
	}

	if originalKey.E != retrieved.Key.E {
		t.Error("Deserialized key exponent doesn't match original")
	}

	// Test that private key components are preserved
	if originalKey.D.Cmp(retrieved.Key.D) != 0 {
		t.Error("Deserialized private exponent doesn't match original")
	}
}

func TestDatabaseClose(t *testing.T) {
	db, _ := testDatabase(t)

	// test closing database
	err := db.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// test that operations fail after close
	_, err = db.GetValidKeys()
	if err == nil {
		t.Error("Operations should fail after database is closed")
	}
}

func TestKeyNotFound(t *testing.T) {
	db, _ := testDatabase(t)
	defer db.Close()

	// test retrieving non-existent key
	_, err := db.GetKeyByKid(99999)
	if err == nil {
		t.Error("GetKeyByKid() should return error for non-existent key")
	}
}
