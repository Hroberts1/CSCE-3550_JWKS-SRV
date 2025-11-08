package db

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"csce-3550_jwks-srv/internal/crypto"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	_ "github.com/mattn/go-sqlite3"
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

// initSchema creates the keys and users tables if they don't exist
func (db *Database) initSchema() error {
	// Create keys table
	keysQuery := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`

	_, err := db.conn.Exec(keysQuery)
	if err != nil {
		return fmt.Errorf("failed to create keys table: %w", err)
	}

	// Create users table for user registration
	usersQuery := `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE,
		date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP      
	);`

	_, err = db.conn.Exec(usersQuery)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create auth_logs table for logging authentication requests
	authLogsQuery := `
	CREATE TABLE IF NOT EXISTS auth_logs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT NOT NULL,
		request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	_, err = db.conn.Exec(authLogsQuery)
	if err != nil {
		return fmt.Errorf("failed to create auth_logs table: %w", err)
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
	database  *Database
	encryptor *crypto.Encryptor
}

func NewManager(dbPath, encryptionKey string) (*Manager, error) {
	// Initialize database - use provided path or default
	var database *Database
	var err error

	if dbPath != "" {
		// Create database with custom path for testing
		database = &Database{path: dbPath}
		err = database.initForManager()
	} else {
		// Use default database creation
		database, err = NewDatabase()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize encryptor
	encryptor, err := crypto.NewEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &Manager{
		database:  database,
		encryptor: encryptor,
	}, nil
}

// initForManager initializes database connection for Manager (similar to initForTest but for production use)
func (db *Database) initForManager() error {
	// ensure directory exists
	if err := os.MkdirAll(filepath.Dir(db.path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// create database file if it doesn't exist
	if _, err := os.Stat(db.path); os.IsNotExist(err) {
		file, err := os.Create(db.path)
		if err != nil {
			return fmt.Errorf("failed to create database file: %w", err)
		}
		file.Close()

		// set restrictive permissions
		if err := os.Chmod(db.path, 0600); err != nil {
			return fmt.Errorf("failed to set database permissions: %w", err)
		}
	}

	// open database connection
	conn, err := sql.Open("sqlite3", db.path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	db.conn = conn

	// initialize schema
	return db.initSchema()
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
	result, err := m.database.conn.Exec(query, encryptedData, expiry.Unix())
	if err != nil {
		return 0, fmt.Errorf("failed to store encrypted key: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get key ID: %w", err)
	}

	return int(id), nil
}

func (m *Manager) GetValidKeys() (map[int]*rsa.PrivateKey, error) {
	return m.getKeys("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
}

func (m *Manager) GetExpiredKeys() (map[int]*rsa.PrivateKey, error) {
	return m.getKeys("SELECT kid, key FROM keys WHERE exp <= ?", time.Now().Unix())
}

func (m *Manager) getKeys(query string, args ...interface{}) (map[int]*rsa.PrivateKey, error) {
	rows, err := m.database.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	keys := make(map[int]*rsa.PrivateKey)
	for rows.Next() {
		var kid int
		var encryptedData []byte

		if err := rows.Scan(&kid, &encryptedData); err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		// Decrypt the PEM data
		pemData, err := m.encryptor.Decrypt(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key %d: %w", kid, err)
		}

		// Parse PEM data back to RSA private key
		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("invalid PEM block for key %d", kid)
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %d: %w", kid, err)
		}

		keys[kid] = privateKey
	}

	return keys, nil
}

// User represents a user record in the database
type User struct {
	ID             int64      `json:"id"`
	Username       string     `json:"username"`
	PasswordHash   string     `json:"-"` // never include in JSON responses
	Email          string     `json:"email"`
	DateRegistered time.Time  `json:"date_registered"`
	LastLogin      *time.Time `json:"last_login,omitempty"`
}

// Argon2 configuration parameters
type Argon2Config struct {
	Time      uint32 // number of iterations
	Memory    uint32 // memory usage in KB
	Threads   uint8  // number of parallel threads
	KeyLength uint32 // length of the derived key
}

// Default Argon2 configuration (recommended values)
var DefaultArgon2Config = Argon2Config{
	Time:      3,         // 3 iterations
	Memory:    64 * 1024, // 64 MB
	Threads:   4,         // 4 threads
	KeyLength: 32,        // 32 bytes key length
}

// CreateUser creates a new user with a generated password
func (db *Database) CreateUser(username, email string) (string, error) {
	// generate secure password using UUIDv4
	password := uuid.New().String()

	// generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// hash password with Argon2
	hash := argon2.IDKey([]byte(password), salt, DefaultArgon2Config.Time,
		DefaultArgon2Config.Memory, DefaultArgon2Config.Threads, DefaultArgon2Config.KeyLength)

	// encode salt and hash for storage (salt:hash format in base64)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	passwordHash := fmt.Sprintf("%s:%s", saltB64, hashB64)

	// insert user into database
	query := `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`
	_, err := db.conn.Exec(query, username, passwordHash, email)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	return password, nil
}

// GetUserByUsername retrieves a user by username
func (db *Database) GetUserByUsername(username string) (*User, error) {
	query := `SELECT id, username, password_hash, email, date_registered, last_login 
			  FROM users WHERE username = ?`

	var user User
	var lastLogin sql.NullTime

	err := db.conn.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.DateRegistered, &lastLogin,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// VerifyPassword verifies a password against the stored hash
func (db *Database) VerifyPassword(username, password string) (bool, error) {
	user, err := db.GetUserByUsername(username)
	if err != nil {
		return false, err
	}

	// split stored hash into salt and hash components
	parts := strings.Split(user.PasswordHash, ":")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid password hash format")
	}

	// decode salt and hash
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	storedHash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// hash the provided password with the same salt
	computedHash := argon2.IDKey([]byte(password), salt, DefaultArgon2Config.Time,
		DefaultArgon2Config.Memory, DefaultArgon2Config.Threads, DefaultArgon2Config.KeyLength)

	// constant time comparison
	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1, nil
}

// CreateUser creates a new user via the manager
func (m *Manager) CreateUser(username, email string) (string, error) {
	return m.database.CreateUser(username, email)
}

// AuthLog represents an authentication log entry
type AuthLog struct {
	ID               int64     `json:"id"`
	RequestIP        string    `json:"request_ip"`
	RequestTimestamp time.Time `json:"request_timestamp"`
	UserID           *int64    `json:"user_id,omitempty"`
}

// LogAuthRequest logs an authentication request to the database
func (db *Database) LogAuthRequest(requestIP string, username string) error {
	// get user ID if username is provided
	var userID *int64
	if username != "" {
		user, err := db.GetUserByUsername(username)
		if err == nil && user != nil {
			userID = &user.ID
		}
		// if user not found, we still log with NULL user_id
	}

	// insert auth log entry
	query := `INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`
	_, err := db.conn.Exec(query, requestIP, userID)
	if err != nil {
		return fmt.Errorf("failed to log auth request: %w", err)
	}

	return nil
}

// GetAuthLogs retrieves authentication logs from the database
func (db *Database) GetAuthLogs(limit int) ([]*AuthLog, error) {
	query := `SELECT id, request_ip, request_timestamp, user_id 
			  FROM auth_logs 
			  ORDER BY request_timestamp DESC`
	
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query auth logs: %w", err)
	}
	defer rows.Close()

	var logs []*AuthLog
	for rows.Next() {
		var log AuthLog
		var userID sql.NullInt64

		err := rows.Scan(&log.ID, &log.RequestIP, &log.RequestTimestamp, &userID)
		if err != nil {
			return nil, fmt.Errorf("failed to scan auth log: %w", err)
		}

		if userID.Valid {
			log.UserID = &userID.Int64
		}

		logs = append(logs, &log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating auth logs: %w", err)
	}

	return logs, nil
}

// LogAuthRequest logs an authentication request via the manager
func (m *Manager) LogAuthRequest(requestIP string, username string) error {
	return m.database.LogAuthRequest(requestIP, username)
}
