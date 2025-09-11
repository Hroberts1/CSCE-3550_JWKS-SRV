package httpserver

import (
	"os"
	"testing"
	"time"
)

func TestNewConfig(t *testing.T) {
	// clear env vars first
	os.Unsetenv("KEY_LIFETIME")
	os.Unsetenv("KEY_RETAIN")
	os.Unsetenv("JWT_LIFETIME")
	os.Unsetenv("ISSUER")

	config, err := NewConfig()
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	// test defaults
	if config.KeyLifetime != 10*time.Minute {
		t.Errorf("Expected KeyLifetime to be 10m, got %v", config.KeyLifetime)
	}

	if config.KeyRetainPeriod != time.Hour {
		t.Errorf("Expected KeyRetainPeriod to be 1h, got %v", config.KeyRetainPeriod)
	}

	if config.JWTLifetime != 5*time.Minute {
		t.Errorf("Expected JWTLifetime to be 5m, got %v", config.JWTLifetime)
	}

	if config.Issuer != "jwks-server" {
		t.Errorf("Expected Issuer to be 'jwks-server', got %v", config.Issuer)
	}
}

func TestNewConfigWithEnvVars(t *testing.T) {
	// set env vars
	os.Setenv("KEY_LIFETIME", "15m")
	os.Setenv("KEY_RETAIN", "2h")
	os.Setenv("JWT_LIFETIME", "10m")
	os.Setenv("ISSUER", "test-issuer")

	defer func() {
		os.Unsetenv("KEY_LIFETIME")
		os.Unsetenv("KEY_RETAIN")
		os.Unsetenv("JWT_LIFETIME")
		os.Unsetenv("ISSUER")
	}()

	config, err := NewConfig()
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	// test env var overrides
	if config.KeyLifetime != 15*time.Minute {
		t.Errorf("Expected KeyLifetime to be 15m, got %v", config.KeyLifetime)
	}

	if config.KeyRetainPeriod != 2*time.Hour {
		t.Errorf("Expected KeyRetainPeriod to be 2h, got %v", config.KeyRetainPeriod)
	}

	if config.JWTLifetime != 10*time.Minute {
		t.Errorf("Expected JWTLifetime to be 10m, got %v", config.JWTLifetime)
	}

	if config.Issuer != "test-issuer" {
		t.Errorf("Expected Issuer to be 'test-issuer', got %v", config.Issuer)
	}
}

func TestNewConfigInvalidDuration(t *testing.T) {
	os.Setenv("KEY_LIFETIME", "invalid")
	defer os.Unsetenv("KEY_LIFETIME")

	_, err := NewConfig()
	if err == nil {
		t.Error("Expected error for invalid KEY_LIFETIME duration")
	}
}

func TestNewConfigInvalidKeyRetain(t *testing.T) {
	os.Setenv("KEY_RETAIN", "not-a-duration")
	defer os.Unsetenv("KEY_RETAIN")

	_, err := NewConfig()
	if err == nil {
		t.Error("Expected error for invalid KEY_RETAIN duration")
	}
}

func TestNewConfigInvalidJWTLifetime(t *testing.T) {
	os.Setenv("JWT_LIFETIME", "bad-duration")
	defer os.Unsetenv("JWT_LIFETIME")

	_, err := NewConfig()
	if err == nil {
		t.Error("Expected error for invalid JWT_LIFETIME duration")
	}
}
