package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"csce-3550_jwks-srv/internal/keys"
)

func TestNewSrv(t *testing.T) {
	config := &Config{
		KeyLifetime:     10 * time.Minute,
		KeyRetainPeriod: time.Hour,
		JWTLifetime:     5 * time.Minute,
		Issuer:          "test-issuer",
		EncryptionKey:   "test-encryption-key-123",
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	server := NewSrv(manager, config)

	if server == nil {
		t.Fatal("NewSrv returned nil")
	}

	if server.config != config {
		t.Error("Server config not set correctly")
	}

	if server.manager != manager {
		t.Error("Server manager not set correctly")
	}

	if server.httpServer == nil {
		t.Error("HTTP server not initialized")
	}
}

func TestHandleJWKS(t *testing.T) {
	config := &Config{
		KeyLifetime:     10 * time.Minute,
		KeyRetainPeriod: time.Hour,
		JWTLifetime:     5 * time.Minute,
		Issuer:          "test-issuer",
		EncryptionKey:   "test-encryption-key-123",
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	manager.Start()
	time.Sleep(100 * time.Millisecond) // allow key generation
	defer manager.Stop()

	server := NewSrv(manager, config)

	// test GET method
	req, err := http.NewRequest("GET", "/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleJWKS)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v",
			contentType, "application/json")
	}

	body := rr.Body.String()
	if !strings.Contains(body, "keys") {
		t.Error("Response does not contain 'keys' field")
	}
}

func TestHandleJWKSMethodNotAllowed(t *testing.T) {
	config := &Config{
		KeyLifetime:     10 * time.Minute,
		KeyRetainPeriod: time.Hour,
		JWTLifetime:     5 * time.Minute,
		Issuer:          "test-issuer",
		EncryptionKey:   "test-encryption-key-123",
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	server := NewSrv(manager, config)

	req, err := http.NewRequest("POST", "/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleJWKS)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusMethodNotAllowed)
	}
}

func TestHandleAuth(t *testing.T) {
	encryptionKey := "test-encryption-key-32-bytes-long" // Match the environment variable
	config := &Config{
		KeyLifetime:     10 * time.Minute,
		KeyRetainPeriod: time.Hour,
		JWTLifetime:     5 * time.Minute,
		Issuer:          "test-issuer",
		EncryptionKey:   encryptionKey,
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	if err := manager.Start(); err != nil {
		t.Fatalf("Manager.Start() error = %v", err)
	}
	defer manager.Stop()

	// Wait longer for key generation
	time.Sleep(3 * time.Second)

	server := NewSrv(manager, config)

	// test POST method
	req, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleAuth)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v (body: %s)",
			status, http.StatusOK, rr.Body.String())
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v",
			contentType, "application/json")
	}

	body := rr.Body.String()
	if !strings.Contains(body, "token") {
		t.Error("Response does not contain 'token' field")
	}
}

func TestHandleAuthWithExpired(t *testing.T) {
	encryptionKey := "test-encryption-key-32-bytes-long" // Match the environment variable
	config := &Config{
		KeyLifetime:     10 * time.Minute,
		KeyRetainPeriod: time.Hour,
		JWTLifetime:     5 * time.Minute,
		Issuer:          "test-issuer",
		EncryptionKey:   encryptionKey,
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	if err := manager.Start(); err != nil {
		t.Fatalf("Manager.Start() error = %v", err)
	}
	defer manager.Stop()

	// Wait longer for key generation
	time.Sleep(3 * time.Second)

	server := NewSrv(manager, config)

	// Wait for the 10-second key to expire
	t.Log("Waiting for 10-second key to expire...")
	time.Sleep(11 * time.Second)

	req, err := http.NewRequest("POST", "/auth?expired=true", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleAuth)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "token") {
		t.Error("Response does not contain 'token' field")
	}
}

func TestHandleAuthMethodNotAllowed(t *testing.T) {
	config := &Config{
		KeyLifetime:     10 * time.Minute,
		KeyRetainPeriod: time.Hour,
		JWTLifetime:     5 * time.Minute,
		Issuer:          "test-issuer",
		EncryptionKey:   "test-encryption-key-123",
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	server := NewSrv(manager, config)

	req, err := http.NewRequest("GET", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleAuth)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusMethodNotAllowed)
	}
}
