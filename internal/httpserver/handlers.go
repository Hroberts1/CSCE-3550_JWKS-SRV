package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"csce-3550_jwks-srv/internal/jwt"
)

// JWKS endpoint handler - GET /jwks
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// get JWKS
	jwks, err := s.manager.GetJWKS()
	if err != nil {
		http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
		return
	}

	// set headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// encode response
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// auth endpoint handler - POST /auth
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// check for expired query param
	expired := r.URL.Query().Get("expired") != ""

	// get signing key
	signingKey := s.manager.GetSigningKey(expired)
	if signingKey == nil {
		http.Error(w, "No signing key available", http.StatusInternalServerError)
		return
	}

	// determine expiry - if expired=true, force expiry in the past
	expiry := s.config.JWTLifetime
	if expired {
		// ensure the token is already expired when returned
		expiry = -1 * time.Minute
	}

	// create JWT
	token, err := jwt.CreateJWT(
		signingKey.PrivateKey,
		signingKey.ID,
		s.config.Issuer,
		expiry,
	)
	if err != nil {
		http.Error(w, "Failed to create JWT", http.StatusInternalServerError)
		return
	}

	// response
	response := map[string]string{
		"token": token,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// RegisterRequest represents the request body for user registration
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// RegisterResponse represents the response body for user registration
type RegisterResponse struct {
	Password string `json:"password"`
}

// register endpoint handler - POST /register
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// parse request body
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// validate input
	if strings.TrimSpace(req.Username) == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Email) == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// create user and get generated password
	password, err := s.manager.CreateUser(req.Username, req.Email)
	if err != nil {
		// check for duplicate username/email errors
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Username or email already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// prepare response
	response := RegisterResponse{
		Password: password,
	}

	// set headers and respond
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// apply middleware chain
func (s *Server) applyMiddleware(handler http.HandlerFunc) http.Handler {
	// chain middleware in reverse order
	h := http.Handler(handler)

	// add middleware stack
	h = RecoveryMiddleware(h)
	h = SecurityHeadersMiddleware(h)
	h = CORSMiddleware(h)
	h = RateLimitMiddleware(h)
	h = LoggingMiddleware(h)

	return h
}
