package keys

import (
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
}

// create new key mgr
func NewManager(keyLifetime, keyRetainPeriod time.Duration) (*Manager, error) {
	database, err := db.NewDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return &Manager{
		keyLifetime:     keyLifetime,
		keyRetainPeriod: keyRetainPeriod,
		keys:            make(map[string]*Key),
		stopCh:          make(chan struct{}),
		database:        database,
	}, nil
}

// start background rotation & cleanup
func (m *Manager) Start() error {
	// generate test keys on startup
	if err := m.database.GenerateAndSaveTestKeys(); err != nil {
		return fmt.Errorf("failed to generate test keys: %w", err)
	}

	// gen initial key
	if err := m.rotateKey(); err != nil {
		return fmt.Errorf("failed to generate initial key: %w", err)
	}

	go m.rotationLoop()
	go m.cleanupLoop()

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

	// close database connection
	if m.database != nil {
		m.database.Close()
	}
}

// get valid keys for JWKS endpoint
func (m *Manager) GetValidKeys() []*Key {
	keyRecords, err := m.database.GetValidKeys()
	if err != nil {
		return []*Key{}
	}

	keys := make([]*Key, 0, len(keyRecords))
	for _, record := range keyRecords {
		key := &Key{
			ID:         strconv.FormatInt(record.Kid, 10),
			CreatedAt:  time.Unix(record.Exp, 0).Add(-m.keyLifetime), // approximate creation time
			ExpiresAt:  time.Unix(record.Exp, 0),
			PrivateKey: record.Key,
			PublicKey:  &record.Key.PublicKey,
		}
		keys = append(keys, key)
	}

	return keys
}

// get signing key for auth endpoint
func (m *Manager) GetSigningKey(expired bool) *Key {
	var keyRecord *db.KeyRecord
	var err error

	if expired {
		// get any expired key from database
		keyRecord, err = m.database.GetAnyExpiredKey()
	} else {
		// get any valid key from database
		keyRecord, err = m.database.GetAnyValidKey()
	}

	if err != nil {
		return nil
	}

	// convert database record to Key struct
	return &Key{
		ID:         strconv.FormatInt(keyRecord.Kid, 10),
		CreatedAt:  time.Unix(keyRecord.Exp, 0).Add(-m.keyLifetime), // approximate creation time
		ExpiresAt:  time.Unix(keyRecord.Exp, 0),
		PrivateKey: keyRecord.Key,
		PublicKey:  &keyRecord.Key.PublicKey,
	}
}

// rotate key - create new current key
func (m *Manager) rotateKey() error {
	newKey, err := GenerateRSAKeyPair()
	if err != nil {
		return err
	}

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
