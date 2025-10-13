package httpserver

import (
	"encoding/json"
	"net/http"
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
