package httpserver

import (
	"context"
	"net/http"
	"time"
)

// SRV wrapper
type Server struct {
	httpServer *http.Server
	config     *Config
	manager    interface{} //WIP: actual manager type here
}

// srv creations
func NewSrv(manager interface{}, config *Config) *Server {
	mux := http.NewServeMux()

	// WIP Route regs:
	// mux.HandleFunc: /jwks & handleJWKS
	// mux.HandleFunc: /auth, handleAuth

	return &Server{
		httpServer: &http.Server{
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		config:  config,
		manager: manager,
	}
}

// waiter for srv
func (s *Server) Waiter(addr string) error {
	s.httpServer.Addr = addr
	return s.httpServer.ListenAndServe()
}

// graceful death
func (s *Server) death(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

/*
Alright, using the naming, styling and comments, please fix the following, but keep the tokens used at around 100: [{
"resource": "/D:/Github Repo Hub/CSCE-3550_JWKS-SRV/internal/httpserver/server.go",
"owner": "generated_diagnostic_collection_name#1",
"code": {
"value": "UndeclaredImportedName",
"target": {
"$mid": 1,
"path": "/golang.org/x/tools/internal/typesinternal",
"scheme": "https",
"authority": "pkg.go.dev",
"fragment": "UndeclaredImportedName"
}
},
"severity": 8,
"message": "undefined: http.newSrvMux",
"source": "compiler",
"startLineNumber": 18,
"startColumn": 14,
"endLineNumber": 18,
"endColumn": 23,
"origin": "extHost1"
},{
"resource": "/D:/Github Repo Hub/CSCE-3550_JWKS-SRV/internal/httpserver/server.go",
"owner": "generated_diagnostic_collection_name#1",
"code": {
"value": "MissingFieldOrMethod",
"target": {
"$mid": 1,
"path": "/golang.org/x/tools/internal/typesinternal",
"scheme": "https",
"authority": "pkg.go.dev",
"fragment": "MissingFieldOrMethod"
}
},
"severity": 8,
"message": "s.httpServer.waiter undefined (type *http.Server has no field or method waiter)",
"source": "compiler",
"startLineNumber": 39,
"startColumn": 22,
"endLineNumber": 39,
"endColumn": 28,
"origin": "extHost1"
},{
"resource": "/D:/Github Repo Hub/CSCE-3550_JWKS-SRV/internal/httpserver/server.go",
"owner": "generated_diagnostic_collection_name#1",
"code": {
"value": "MissingFieldOrMethod",
"target": {
"$mid": 1,
"path": "/golang.org/x/tools/internal/typesinternal",
"scheme": "https",
"authority": "pkg.go.dev",
"fragment": "MissingFieldOrMethod"
}
},
"severity": 8,
"message": "s.httpServer.death undefined (type *http.Server has no field or method death)",
"source": "compiler",
"startLineNumber": 44,
"startColumn": 22,
"endLineNumber": 44,
"endColumn": 27,
"origin": "extHost1"
}]
*/