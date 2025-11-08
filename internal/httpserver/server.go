package httpserver

import (
	"context"
	"net/http"
	"time"

	"csce-3550_jwks-srv/internal/keys"
)

// SRV wrapper
type Server struct {
	httpServer *http.Server
	config     *Config
	manager    *keys.Manager
}

// srv creations
func NewSrv(manager *keys.Manager, config *Config) *Server {
	srv := &Server{
		config:  config,
		manager: manager,
	}

	mux := http.NewServeMux()

	// route regs w/ middleware
	mux.Handle("/jwks", srv.applyMiddleware(srv.handleJWKS))
	mux.Handle("/.well-known/jwks.json", srv.applyMiddleware(srv.handleJWKS))
	mux.Handle("/auth", srv.applyMiddleware(srv.handleAuth))
	mux.Handle("/register", srv.applyMiddleware(srv.handleRegister))

	srv.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return srv
}

// waiter for srv
func (s *Server) Waiter(addr string) error {
	s.httpServer.Addr = addr
	return s.httpServer.ListenAndServe()
}

// graceful death
func (s *Server) Death(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the underlying HTTP handler for testing
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}
