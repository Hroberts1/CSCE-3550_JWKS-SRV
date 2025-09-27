# Copilot Instructions for This Repository

## Project Style
- Use idiomatic Go project structure:
  - Entrypoint in `cmd/<app>/main.go`
  - Core logic in `internal/<package>`
  - Separate concerns:
    - `httpserver`: API + middleware
    - `keys`: key rotation and JWKS handling
    - `jwt`: JWT encoding/decoding
    - `database`: SQLite persistence

## Coding Style
- Imports grouped: stdlib, third-party, local.
- Variable naming:
  - camelCase for variables and functions
  - PascalCase for exported symbols
  - Use abbreviations such as JWT, ID
- Config loaded from environment variables with sane defaults.
- Always implement graceful shutdowns, context cancellation, and signal handling.

## Security Defaults
- Enforce CORS, CSP, and XSS protection headers.
- Apply token bucket rate limiting by default.
- Keys:
  - RSA 2048-bit by default (configurable to 3072/4096)
  - Automatic rotation and retention
  - Expired keys returned only when explicitly requested
- Database:
  - Use SQLite for persistence
  - Always use parameterized queries to prevent SQL injection
  - Restrict DB file permissions

## Testing
- Use table-driven tests for functions.
- Use `httptest` for endpoint testing.
- Add integration tests for SQLite persistence.
- Target at least 80% coverage across all packages.
  - Ensure the SQLite DB file is created and accessible.

## Documentation
- README must explain purpose, endpoints, SQLite integration, and environment variables.
- Inline comments only when necessary:
  - Short, lowercase section labels (e.g. `// graceful death`, `// srv creations`)
  - Middleware notes with intent (e.g. `// timeout middleware - enforces request timeouts`)
  - Focus on **why**, not **how**
- Code should pass `go fmt`, `go vet`, and static analysis.
- Always highlight SQL injection prevention and SQLite’s persistence model.

---
