package httpserver

import (
	"context"
	"net/http"
	"time"
)

// SRV wrapper
type Server struct {
	http.Server *http.Server
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