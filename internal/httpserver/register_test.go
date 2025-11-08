package httpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"csce-3550_jwks-srv/internal/keys"
)

func TestRegisterHandler(t *testing.T) {
	// create test key manager with unique encryption key
	testKey := fmt.Sprintf("test-key-%d-chars-long-for-aes256", time.Now().UnixNano())
	if len(testKey) < 32 {
		testKey = testKey + "0123456789012345678901234567890123456789"
	}
	testKey = testKey[:32]
	
	manager, err := keys.NewManager(time.Hour, time.Hour*24, testKey)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// create test config
	config := &Config{
		KeyLifetime:     time.Hour,
		KeyRetainPeriod: time.Hour * 24,
		JWTLifetime:     time.Minute * 30,
		Issuer:          "test-issuer",
		EncryptionKey:   testKey,
	}

	// create test server
	server := NewSrv(manager, config)

	testId := time.Now().UnixNano()
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectPassword bool
	}{
		{
			name: "Valid registration",
			requestBody: RegisterRequest{
				Username: fmt.Sprintf("testuser-%d", testId),
				Email:    fmt.Sprintf("test-%d@example.com", testId),
			},
			expectedStatus: http.StatusCreated,
			expectPassword: true,
		},
		{
			name: "Missing username",
			requestBody: RegisterRequest{
				Username: "",
				Email:    fmt.Sprintf("test-%d@example.com", testId+1),
			},
			expectedStatus: http.StatusBadRequest,
			expectPassword: false,
		},
		{
			name: "Missing email",
			requestBody: RegisterRequest{
				Username: fmt.Sprintf("testuser2-%d", testId+2),
				Email:    "",
			},
			expectedStatus: http.StatusBadRequest,
			expectPassword: false,
		},
		{
			name: "Whitespace only username",
			requestBody: RegisterRequest{
				Username: "   ",
				Email:    fmt.Sprintf("test-%d@example.com", testId+3),
			},
			expectedStatus: http.StatusBadRequest,
			expectPassword: false,
		},
		{
			name: "Whitespace only email",
			requestBody: RegisterRequest{
				Username: fmt.Sprintf("testuser3-%d", testId+4),
				Email:    "   ",
			},
			expectedStatus: http.StatusBadRequest,
			expectPassword: false,
		},
		{
			name:           "Invalid JSON",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectPassword: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// marshal request body
			var body []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			// create request
			req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			// create response recorder
			rr := httptest.NewRecorder()

			// call handler
			server.handleRegister(rr, req)

			// check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// check response for successful registration
			if tt.expectPassword && rr.Code == http.StatusCreated {
				var response RegisterResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
					return
				}

				if response.Password == "" {
					t.Error("Expected non-empty password in response")
				}

				// verify password is UUIDv4 format (36 characters with dashes)
				if len(response.Password) != 36 {
					t.Errorf("Expected password length 36, got %d", len(response.Password))
				}
			}

			// check Content-Type for successful responses
			if rr.Code == http.StatusCreated {
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %s", contentType)
				}
			}
		})
	}
}

func TestRegisterHandlerMethodNotAllowed(t *testing.T) {
	// create test key manager with unique encryption key
	testKey := fmt.Sprintf("test-key-%d-chars-long-for-aes256", time.Now().UnixNano())
	if len(testKey) < 32 {
		testKey = testKey + "0123456789012345678901234567890123456789"
	}
	testKey = testKey[:32]
	
	manager, err := keys.NewManager(time.Hour, time.Hour*24, testKey)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// create test config
	config := &Config{
		KeyLifetime:     time.Hour,
		KeyRetainPeriod: time.Hour * 24,
		JWTLifetime:     time.Minute * 30,
		Issuer:          "test-issuer",
		EncryptionKey:   testKey,
	}

	// create test server
	server := NewSrv(manager, config)

	// test non-POST methods
	methods := []string{"GET", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run("Method_"+method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/register", nil)
			rr := httptest.NewRecorder()

			server.handleRegister(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d for %s method, got %d", 
					http.StatusMethodNotAllowed, method, rr.Code)
			}
		})
	}
}

func TestRegisterHandlerDuplicateUser(t *testing.T) {
	// create test key manager with unique encryption key
	testKey := fmt.Sprintf("test-key-%d-chars-long-for-aes256", time.Now().UnixNano())
	if len(testKey) < 32 {
		testKey = testKey + "0123456789012345678901234567890123456789"
	}
	testKey = testKey[:32]
	
	manager, err := keys.NewManager(time.Hour, time.Hour*24, testKey)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// create test config
	config := &Config{
		KeyLifetime:     time.Hour,
		KeyRetainPeriod: time.Hour * 24,
		JWTLifetime:     time.Minute * 30,
		Issuer:          "test-issuer",
		EncryptionKey:   testKey,
	}

	// create test server
	server := NewSrv(manager, config)

	testId := time.Now().UnixNano()
	// register first user
	reqBody1 := RegisterRequest{
		Username: fmt.Sprintf("duplicateuser-%d", testId),
		Email:    fmt.Sprintf("duplicate-%d@example.com", testId),
	}

	body1, _ := json.Marshal(reqBody1)
	req1 := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body1))
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()

	server.handleRegister(rr1, req1)

	if rr1.Code != http.StatusCreated {
		t.Fatalf("First registration should succeed, got status %d", rr1.Code)
	}

	// try to register same user again
	reqBody2 := RegisterRequest{
		Username: fmt.Sprintf("duplicateuser-%d", testId), // same username
		Email:    fmt.Sprintf("different-%d@example.com", testId),
	}

	body2, _ := json.Marshal(reqBody2)
	req2 := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body2))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()

	server.handleRegister(rr2, req2)

	if rr2.Code != http.StatusConflict {
		t.Errorf("Duplicate username should return %d, got %d", 
			http.StatusConflict, rr2.Code)
	}

	// try to register with same email
	reqBody3 := RegisterRequest{
		Username: fmt.Sprintf("differentuser-%d", testId),
		Email:    fmt.Sprintf("duplicate-%d@example.com", testId), // same email
	}

	body3, _ := json.Marshal(reqBody3)
	req3 := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body3))
	req3.Header.Set("Content-Type", "application/json")
	rr3 := httptest.NewRecorder()

	server.handleRegister(rr3, req3)

	if rr3.Code != http.StatusConflict {
		t.Errorf("Duplicate email should return %d, got %d", 
			http.StatusConflict, rr3.Code)
	}
}