package keys

import (
	"sync"
	"time"
)

// key mgr - handles RSA key pairs w/ rotation
type Manager struct {
	keyLifetime     time.Duration
	keyRetainPeriod time.Duration
	keys            map[string]*Key
	currentKey      *Key
	mu              sync.RWMutex
	stopCh          chan struct{}
}

// create new key mgr
func NewManager(keyLifetime, keyRetainPeriod time.Duration) *Manager {
	return &Manager{
		keyLifetime:     keyLifetime,
		keyRetainPeriod: keyRetainPeriod,
		keys:            make(map[string]*Key),
		stopCh:          make(chan struct{}),
	}
}

// start background rotation & cleanup
func (m *Manager) Start() {
	// gen initial key
	if err := m.rotateKey(); err != nil {
		// TODO: handle initial key gen error
		return
	}

	go m.rotationLoop()
	go m.cleanupLoop()
}

// stop mgr
func (m *Manager) Stop() {
	close(m.stopCh)
}

// get valid keys for JWKS endpoint
func (m *Manager) GetValidKeys() []*Key {
	m.mu.RLock()
	defer m.mu.RUnlock()

	validKeys := make([]*Key, 0)
	now := time.Now()

	for _, key := range m.keys {
		if !key.IsExpired(now) {
			validKeys = append(validKeys, key)
		}
	}

	return validKeys
}

// get signing key for auth endpoint
func (m *Manager) GetSigningKey(expired bool) *Key {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if expired {
		// find first expired key
		now := time.Now()
		for _, key := range m.keys {
			if key.IsExpired(now) {
				return key
			}
		}
	}

	return m.currentKey
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
