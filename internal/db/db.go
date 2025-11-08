package db

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/your-repo/internal/crypto"
)

// Database represents our SQLite database connection
type Database struct {
	conn *sql.DB
	path string
}

// KeyRecord represents a key record in the database
type KeyRecord struct {
	Kid int64
	Key *rsa.PrivateKey
	Exp int64
}

const (
	dbFileName = "totally_not_my_privateKeys.db"
	dataDir    = "internal/data"
)

// NewDatabase creates a new database instance and ensures the database file exists
func NewDatabase() (*Database, error) {
	// construct path to database file
	dbPath := filepath.Join(dataDir, dbFileName)

	// ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// check if database file exists, create if not
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// create empty file
		file, err := os.Create(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create database file: %w", err)
		}
		file.Close()

		// set restrictive permissions on database file
		if err := os.Chmod(dbPath, 0600); err != nil {
			return nil, fmt.Errorf("failed to set database file permissions: %w", err)
		}
	}

	// open database connection
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &Database{
		conn: conn,
		path: dbPath,
	}

	// initialize database schema
	if err := db.initSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return db, nil
}

// initSchema creates the keys table if it doesn't exist
func (db *Database) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`

	_, err := db.conn.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create keys table: %w", err)
	}

	return nil
}

// SaveKey saves a private key to the database using PKCS1 PEM encoding
func (db *Database) SaveKey(privateKey *rsa.PrivateKey, expTime time.Time) (int64, error) {
	// serialize private key to PKCS1 PEM format
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// convert expiration time to Unix timestamp
	expUnix := expTime.Unix()

	// insert into database
	query := `INSERT INTO keys (key, exp) VALUES (?, ?);`
	result, err := db.conn.Exec(query, pemData, expUnix)
	if err != nil {
		return 0, fmt.Errorf("failed to insert key into database: %w", err)
	}

	// get the inserted key ID
	kid, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get inserted key ID: %w", err)
	}

	return kid, nil
}

// GetValidKeys returns all keys that have not expired
func (db *Database) GetValidKeys() ([]*KeyRecord, error) {
	now := time.Now().Unix()
	query := `SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC;`

	rows, err := db.conn.Query(query, now)
	if err != nil {
		return nil, fmt.Errorf("failed to query valid keys: %w", err)
	}
	defer rows.Close()

	var keys []*KeyRecord
	for rows.Next() {
		var kid, exp int64
		var keyData []byte

		if err := rows.Scan(&kid, &keyData, &exp); err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// deserialize PEM data back to private key
		privateKey, err := deserializePEMKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize key for kid %d: %w", kid, err)
		}

		keys = append(keys, &KeyRecord{
			Kid: kid,
			Key: privateKey,
			Exp: exp,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during key iteration: %w", err)
	}

	return keys, nil
}

// GetExpiredKeys returns all keys that have expired
func (db *Database) GetExpiredKeys() ([]*KeyRecord, error) {
	now := time.Now().Unix()
	query := `SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC;`

	rows, err := db.conn.Query(query, now)
	if err != nil {
		return nil, fmt.Errorf("failed to query expired keys: %w", err)
	}
	defer rows.Close()

	var keys []*KeyRecord
	for rows.Next() {
		var kid, exp int64
		var keyData []byte

		if err := rows.Scan(&kid, &keyData, &exp); err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// deserialize PEM data back to private key
		privateKey, err := deserializePEMKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize key for kid %d: %w", kid, err)
		}

		keys = append(keys, &KeyRecord{
			Kid: kid,
			Key: privateKey,
			Exp: exp,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during key iteration: %w", err)
	}

	return keys, nil
}

// GetKeyByKid retrieves a specific key by its ID
func (db *Database) GetKeyByKid(kid int64) (*KeyRecord, error) {
	query := `SELECT kid, key, exp FROM keys WHERE kid = ?;`

	var expTime int64
	var keyData []byte

	err := db.conn.QueryRow(query, kid).Scan(&kid, &keyData, &expTime)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key with kid %d not found", kid)
		}
		return nil, fmt.Errorf("failed to query key by kid: %w", err)
	}

	// deserialize PEM data back to private key
	privateKey, err := deserializePEMKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize key for kid %d: %w", kid, err)
	}

	return &KeyRecord{
		Kid: kid,
		Key: privateKey,
		Exp: expTime,
	}, nil
}

// GetAnyValidKey returns the first available valid (non-expired) key
func (db *Database) GetAnyValidKey() (*KeyRecord, error) {
	now := time.Now().Unix()
	query := `SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1;`

	var kid, exp int64
	var keyData []byte

	err := db.conn.QueryRow(query, now).Scan(&kid, &keyData, &exp)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no valid keys available")
		}
		return nil, fmt.Errorf("failed to query valid key: %w", err)
	}

	// deserialize PEM data back to private key
	privateKey, err := deserializePEMKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize key for kid %d: %w", kid, err)
	}

	return &KeyRecord{
		Kid: kid,
		Key: privateKey,
		Exp: exp,
	}, nil
}

// GetAnyExpiredKey returns the first available expired key
func (db *Database) GetAnyExpiredKey() (*KeyRecord, error) {
	now := time.Now().Unix()
	query := `SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1;`

	var kid, exp int64
	var keyData []byte

	err := db.conn.QueryRow(query, now).Scan(&kid, &keyData, &exp)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no expired keys available")
		}
		return nil, fmt.Errorf("failed to query expired key: %w", err)
	}

	// deserialize PEM data back to private key
	privateKey, err := deserializePEMKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize key for kid %d: %w", kid, err)
	}

	return &KeyRecord{
		Kid: kid,
		Key: privateKey,
		Exp: exp,
	}, nil
}

// GenerateAndSaveTestKeys creates 3 test keys with different expiry times
func (db *Database) GenerateAndSaveTestKeys() error {
	// import key generation functionality
	keyPairs := []struct {
		name     string
		duration time.Duration
	}{
		{"10 second key", 10 * time.Second},
		{"5 minute key", 5 * time.Minute},
		{"1 hour key", 1 * time.Hour},
	}

	for _, kp := range keyPairs {
		// generate RSA key pair
		privateKey, err := generateRSAKey(2048)
		if err != nil {
			return fmt.Errorf("failed to generate %s: %w", kp.name, err)
		}

		// calculate expiry time
		expTime := time.Now().Add(kp.duration)

		// save to database
		kid, err := db.SaveKey(privateKey, expTime)
		if err != nil {
			return fmt.Errorf("failed to save %s: %w", kp.name, err)
		}

		fmt.Printf("Generated %s with kid: %d, expires: %s\n", kp.name, kid, expTime.Format(time.RFC3339))
	}

	return nil
}

// Close closes the database connection
func (db *Database) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

// generateRSAKey generates a new RSA private key with the specified bit size
func generateRSAKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return privateKey, nil
}

// deserializePEMKey converts PEM-encoded bytes back to an RSA private key
func deserializePEMKey(pemData []byte) (*rsa.PrivateKey, error) {
	// decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// parse PKCS1 private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}

	return privateKey, nil
}

type Manager struct {
	db        *sql.DB
	encryptor *crypto.Encryptor
}

func NewManager(dbPath, encryptionKey string) (*Manager, error) {
	// Initialize database
	db, err := NewDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize encryptor
	encryptor, err := crypto.NewEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Manager{
		db:        db,
		encryptor: encryptor,
	}, nil
}
func (m *Manager) StoreKey(privateKey *rsa.PrivateKey, expiry time.Time) (int, error) {
	// Serialize to PKCS1 PEM format
	pkcs1Bytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1Bytes,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Encrypt the PEM data
	encryptedData, err := m.encryptor.Encrypt(pemData)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Store encrypted data in database
	query := "INSERT INTO keys (key, exp) VALUES (?, ?)"
	result, err := m.db.Exec(query, encryptedData, expiry.Unix())
	if err != nil {
		return 0, fmt.Errorf("failed to store encrypted key: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get key ID: %w", err)
	}

	return int(id), nil
}

