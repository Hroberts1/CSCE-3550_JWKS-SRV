package keys

import (
	"crypto/rsa"
	"fmt"
	"strconv"
	"sync"
	"time"

	"csce-3550_jwks-srv/internal/db"
)

// key mgr - handles RSA key pairs w/ rotation
type Manager struct {
	keyLifetime     time.Duration
	keyRetainPeriod time.Duration
	keys            map[string]*Key
	currentKey      *Key
	mu              sync.RWMutex
	stopCh          chan struct{}
	database        *db.Database
	dbManager       *db.Manager
}

// create new key mgr
func NewManager(keyLifetime, keyRetainPeriod time.Duration, encryptionKey string) (*Manager, error) {
	// Use encryption key from config - this creates the database with schema
	dbManager, err := db.NewManager("", encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create database manager: %w", err)
	}

	// No need for separate database instance - use the encrypted manager's database
	return &Manager{
		keyLifetime:     keyLifetime,
		keyRetainPeriod: keyRetainPeriod,
		keys:            make(map[string]*Key),
		stopCh:          make(chan struct{}),
		database:        nil, // Remove dual database setup
		dbManager:       dbManager,
	}, nil
}

// start background rotation & cleanup
func (m *Manager) Start() error {
	// generate encrypted test keys on startup
	if err := m.generateEncryptedTestKeys(); err != nil {
		return fmt.Errorf("failed to generate encrypted test keys: %w", err)
	}

	// gen initial key
	if err := m.rotateKey(); err != nil {
		return fmt.Errorf("failed to generate initial key: %w", err)
	}

	go m.rotationLoop()
	go m.cleanupLoop()

	return nil
}

// generateEncryptedTestKeys creates 3 encrypted test keys with different expiry times
func (m *Manager) generateEncryptedTestKeys() error {
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
		privateKey, err := GenerateRSAKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate %s: %w", kp.name, err)
		}

		// calculate expiry time
		expTime := time.Now().Add(kp.duration)

		// save to encrypted database
		kid, err := m.dbManager.StoreKey(privateKey.PrivateKey, expTime)
		if err != nil {
			return fmt.Errorf("failed to save encrypted %s: %w", kp.name, err)
		}

		fmt.Printf("Generated encrypted %s with kid: %d, expires: %s\n", kp.name, kid, expTime.Format(time.RFC3339))
	}

	return nil
}

// stop mgr
func (m *Manager) Stop() {
	select {
	case <-m.stopCh:
		// already closed
	default:
		close(m.stopCh)
	}

	// No need to close database - it's handled by dbManager
}

// get valid keys for JWKS endpoint
func (m *Manager) GetValidKeys() []*Key {
	// try encrypted keys first
	encryptedKeys, err := m.dbManager.GetValidKeys()
	if err == nil && len(encryptedKeys) > 0 {
		keys := make([]*Key, 0, len(encryptedKeys))
		for kidInt, privateKey := range encryptedKeys {
			key := &Key{
				ID:         strconv.Itoa(kidInt),
				CreatedAt:  time.Now().Add(-m.keyLifetime), // approximate creation time
				ExpiresAt:  time.Now().Add(m.keyLifetime),  // approximate expiry time
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
			}
			keys = append(keys, key)
		}
		return keys
	}

	// if no encrypted keys found, return empty slice
	return []*Key{}
}

// get signing key for auth endpoint
func (m *Manager) GetSigningKey(expired bool) *Key {
	// try encrypted keys first
	var encryptedKeys map[int]*rsa.PrivateKey
	var err error

	if expired {
		encryptedKeys, err = m.dbManager.GetExpiredKeys()
	} else {
		encryptedKeys, err = m.dbManager.GetValidKeys()
	}

	if err == nil && len(encryptedKeys) > 0 {
		// return first available encrypted key
		for kidInt, privateKey := range encryptedKeys {
			return &Key{
				ID:         strconv.Itoa(kidInt),
				CreatedAt:  time.Now().Add(-m.keyLifetime), // approximate creation time
				ExpiresAt:  time.Now().Add(m.keyLifetime),  // approximate expiry time
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
			}
		}
	}

	// no encrypted keys found
	return nil
}

// rotate key - create new current key
func (m *Manager) rotateKey() error {
	newKey, err := GenerateRSAKeyPair()
	if err != nil {
		return err
	}

	// store the new key in encrypted database
	expiry := time.Now().Add(m.keyLifetime)
	kidInt, err := m.dbManager.StoreKey(newKey.PrivateKey, expiry)
	if err != nil {
		return fmt.Errorf("failed to store encrypted key: %w", err)
	}

	// update the key ID to match database
	newKey.ID = fmt.Sprintf("%d", kidInt)
	newKey.ExpiresAt = expiry

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[newKey.ID] = newKey
	m.currentKey = newKey

	return nil
}

// background rotation loop
func (m *Manager) rotationLoop() {
	ticker := time.NewTicker(m.keyLifetime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.rotateKey()
		case <-m.stopCh:
			return
		}
	}
}

// background cleanup loop - remove old expired keys
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(time.Hour) // cleanup every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.stopCh:
			return
		}
	}
}

// cleanup expired keys beyond retain period
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	retainUntil := now.Add(-m.keyRetainPeriod)

	for id, key := range m.keys {
		if key.ExpiresAt.Before(retainUntil) {
			delete(m.keys, id)
		}
	}
}

// CreateUser creates a new user via the database manager
func (m *Manager) CreateUser(username, email string) (string, error) {
	return m.dbManager.CreateUser(username, email)
}

// LogAuthRequest logs an authentication request via the database manager
func (m *Manager) LogAuthRequest(requestIP string, username string) error {
	return m.dbManager.LogAuthRequest(requestIP, username)
}
