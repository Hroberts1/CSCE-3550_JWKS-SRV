package httpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"csce-3550_jwks-srv/internal/keys"
)

func TestAuthRateLimiting(t *testing.T) {
	config := &Config{
		KeyLifetime:     10 * time.Second,
		KeyRetainPeriod: 1 * time.Hour,
		JWTLifetime:     1 * time.Hour,
		Issuer:          "test-issuer",
		EncryptionKey:   os.Getenv("NOT_MY_KEY"),
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	manager.Start()
	time.Sleep(100 * time.Millisecond) // allow key generation
	defer manager.Stop()

	server := NewSrv(manager, config)

	// create a test request through the middleware stack
	makeRequest := func() *httptest.ResponseRecorder {
		req, err := http.NewRequest("POST", "/auth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.RemoteAddr = "192.168.1.1:12345" // consistent IP for rate limiting

		rr := httptest.NewRecorder()
		handler := server.applyAuthMiddleware(server.handleAuth)
		handler.ServeHTTP(rr, req)
		return rr
	}

	// make 10 successful requests (within rate limit)
	for i := 0; i < 10; i++ {
		rr := makeRequest()
		if rr.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rr.Code)
		}
	}

	// 11th request should be rate limited
	rr := makeRequest()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests after 10 requests, got %d", rr.Code)
	}

	// wait for token refill (100ms per token for 10 req/sec)
	time.Sleep(200 * time.Millisecond)

	// should be able to make 2 more requests now (2 tokens refilled)
	for i := 0; i < 2; i++ {
		rr := makeRequest()
		if rr.Code != http.StatusOK {
			t.Errorf("After refill, request %d: expected 200, got %d", i+1, rr.Code)
		}
	}

	// next request should be rate limited again
	rr = makeRequest()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests after consuming refilled tokens, got %d", rr.Code)
	}
}

func TestAuthRateLimitingDoesNotAffectOtherEndpoints(t *testing.T) {
	config := &Config{
		KeyLifetime:     10 * time.Second,
		KeyRetainPeriod: 1 * time.Hour,
		JWTLifetime:     1 * time.Hour,
		Issuer:          "test-issuer",
		EncryptionKey:   os.Getenv("NOT_MY_KEY"),
	}

	manager, err := keys.NewManager(config.KeyLifetime, config.KeyRetainPeriod, config.EncryptionKey)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	manager.Start()
	time.Sleep(100 * time.Millisecond)
	defer manager.Stop()

	server := NewSrv(manager, config)

	// exhaust auth rate limit
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("POST", "/auth", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		handler := server.applyAuthMiddleware(server.handleAuth)
		handler.ServeHTTP(rr, req)
	}

	// verify auth is rate limited
	authReq, _ := http.NewRequest("POST", "/auth", nil)
	authReq.RemoteAddr = "192.168.1.1:12345"
	authRR := httptest.NewRecorder()
	authHandler := server.applyAuthMiddleware(server.handleAuth)
	authHandler.ServeHTTP(authRR, authReq)
	if authRR.Code != http.StatusTooManyRequests {
		t.Errorf("Auth endpoint should be rate limited, got status %d", authRR.Code)
	}

	// verify /jwks still works
	jwksReq, _ := http.NewRequest("GET", "/jwks", nil)
	jwksReq.RemoteAddr = "192.168.1.1:12345"
	jwksRR := httptest.NewRecorder()
	jwksHandler := server.applyMiddleware(server.handleJWKS)
	jwksHandler.ServeHTTP(jwksRR, jwksReq)
	if jwksRR.Code != http.StatusOK {
		t.Errorf("JWKS endpoint should not be rate limited, got status %d", jwksRR.Code)
	}
}
