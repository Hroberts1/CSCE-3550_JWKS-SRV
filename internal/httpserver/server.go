package httpserver

import (
	"context"
	"net/http"
	"time"
)

// SRV wrapper
type Server struct {
	httpServer *http.Server
	config *Config
	manager interface{} //WIP: actual manager type here
}

// srv creations
func NewSrv(manager interface{}, config *Config) *Server {
	mux := http.newSrvMux()

	// WIP Route regs:
		// mux.HandleFun: /jwks & handleJWKS
		// mux.HandleFunc: /auth, handleAuth

	return &Server{
		httpServer:	&http.Server{
			Handler:	mux,
			ReadTimeout:	15 * time.Second,
			WriteTimeout:	15 * time.Second,
			IdleTimeout:	60 * time.Second,
		},
		config:	config,
		manager: manager,
	}
}

// waiter for srv
func (s *Server) Waiter(addr string) error{
	s.httpServer.Addr = addr
	return s.httpServer.waiter()
}

// graceful death
func (s *Server) death(ctx context.Context) error{
	return s.httpServer.death(ctx)
}