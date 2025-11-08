package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"csce-3550_jwks-srv/internal/httpserver"
	"csce-3550_jwks-srv/internal/keys"
)

func TestRegisterEndpointIntegration(t *testing.T) {
	// create test key manager with unique encryption key for this test
	testKey := fmt.Sprintf("test-key-%d-chars-long-for-aes256", time.Now().UnixNano())
	if len(testKey) < 32 {
		testKey = testKey + "0123456789012345678901234567890123456789" // pad to ensure 32+ chars
	}
	testKey = testKey[:32] // ensure exactly 32 chars

	manager, err := keys.NewManager(time.Hour, time.Hour*24, testKey)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// create test config
	config := &httpserver.Config{
		KeyLifetime:     time.Hour,
		KeyRetainPeriod: time.Hour * 24,
		JWTLifetime:     time.Minute * 30,
		Issuer:          "test-issuer",
		EncryptionKey:   testKey,
	}

	// create test server
	server := httpserver.NewSrv(manager, config)

	// create test HTTP server
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	// test data with unique username to avoid conflicts
	registrationData := map[string]string{
		"username": fmt.Sprintf("integrationuser-%d", time.Now().UnixNano()),
		"email":    fmt.Sprintf("integration-%d@example.com", time.Now().UnixNano()),
	}

	// marshal request body
	jsonData, err := json.Marshal(registrationData)
	if err != nil {
		t.Fatalf("Failed to marshal request data: %v", err)
	}

	// make POST request to /register
	resp, err := http.Post(ts.URL+"/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to make POST request: %v", err)
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}

	// check content type
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", resp.Header.Get("Content-Type"))
	}

	// read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// parse response
	var response map[string]string
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// check password field exists
	password, exists := response["password"]
	if !exists {
		t.Error("Expected password field in response")
	}

	if password == "" {
		t.Error("Expected non-empty password")
	}

	// verify password is UUIDv4 format (36 characters with 4 dashes)
	if len(password) != 36 {
		t.Errorf("Expected password length 36, got %d", len(password))
	}

	fmt.Printf("Successfully registered user '%s' with password: %s\n",
		registrationData["username"], password)
}

func TestRegisterEndpointDuplicateIntegration(t *testing.T) {
	// create test key manager with unique encryption key for this test
	testKey := fmt.Sprintf("test-key-%d-chars-long-for-aes256", time.Now().UnixNano())
	if len(testKey) < 32 {
		testKey = testKey + "0123456789012345678901234567890123456789" // pad to ensure 32+ chars
	}
	testKey = testKey[:32] // ensure exactly 32 chars

	manager, err := keys.NewManager(time.Hour, time.Hour*24, testKey)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// create test config
	config := &httpserver.Config{
		KeyLifetime:     time.Hour,
		KeyRetainPeriod: time.Hour * 24,
		JWTLifetime:     time.Minute * 30,
		Issuer:          "test-issuer",
		EncryptionKey:   testKey,
	}

	// create test server
	server := httpserver.NewSrv(manager, config)

	// create test HTTP server
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	// test data with unique names for this test
	registrationData := map[string]string{
		"username": fmt.Sprintf("duplicateuser-%d", time.Now().UnixNano()),
		"email":    fmt.Sprintf("duplicate-%d@example.com", time.Now().UnixNano()),
	}

	jsonData, _ := json.Marshal(registrationData)

	// register user first time - should succeed
	resp1, err := http.Post(ts.URL+"/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to make first POST request: %v", err)
	}
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusCreated {
		t.Errorf("First registration should succeed, got status %d", resp1.StatusCode)
	}

	// try to register same user again - should fail with conflict
	resp2, err := http.Post(ts.URL+"/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to make second POST request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("Duplicate registration should return %d, got %d",
			http.StatusConflict, resp2.StatusCode)
	}
}
