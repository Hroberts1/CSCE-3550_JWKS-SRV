package httpserver

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// req logging middleware
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, duration)
	})
}

// status code wrapper
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// CORS middleware - handles cross-origin requests
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rate limiter structure
type rateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
}

type visitor struct {
	limiter  *tokenBucket
	lastSeen time.Time
}

type tokenBucket struct {
	tokens       int
	capacity     int
	refillRate   time.Duration
	lastRefill   time.Time
	windowStart  time.Time
	requestCount int
	mu           sync.Mutex
}

// Global rate limiter for auth endpoint - 10 requests per second
var authRateLimiter = &rateLimiter{
	visitors: make(map[string]*visitor),
}

// rate limiting middleware - prevents abuse (general use)
func RateLimitMiddleware(next http.Handler) http.Handler {
	limiter := &rateLimiter{
		visitors: make(map[string]*visitor),
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !limiter.allow(ip, 10, time.Minute) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AuthRateLimitMiddleware - specific rate limiter for /auth endpoint (10 req/sec)
func AuthRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		// For 10 req/sec: 1 token refills every 100ms (time.Second / 10)
		if !authRateLimiter.allow(ip, 10, time.Second/10) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		return ip[:idx]
	}
	return ip
}

func (rl *rateLimiter) allow(ip string, capacity int, refillRate time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	vis, exists := rl.visitors[ip]
	if !exists {
		vis = &visitor{
			limiter: &tokenBucket{
				tokens:       capacity,
				capacity:     capacity,
				refillRate:   refillRate,
				lastRefill:   time.Now(),
				windowStart:  time.Now(),
				requestCount: 0,
			},
			lastSeen: time.Now(),
		}
		rl.visitors[ip] = vis
	}

	vis.lastSeen = time.Now()
	return vis.limiter.consume()
}

func (tb *tokenBucket) consume() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()

	// Check if we need to reset the window (1 second has passed)
	if now.Sub(tb.windowStart) >= time.Second {
		tb.windowStart = now
		tb.requestCount = 0
		log.Printf("[Rate Limit] Window reset, counter set to 0")
	}

	// Check if we've exceeded the limit in the current window
	if tb.requestCount >= tb.capacity {
		log.Printf("[Rate Limit] Request limit reached (%d/%d), request blocked", tb.requestCount, tb.capacity)
		return false
	}

	// Allow the request
	tb.requestCount++
	log.Printf("[Rate Limit] Request allowed (%d/%d)", tb.requestCount, tb.capacity)
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// content-type validation middleware
func ContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// recovery middleware - catches panics
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered: %v\n%s", err, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// security headers middleware - hardens srv
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// request ID middleware - adds unique IDs for tracing
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), r.RemoteAddr)
		ctx := context.WithValue(r.Context(), "reqID", reqID)
		w.Header().Set("X-Request-ID", reqID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// timeout middleware - enforces request timeouts
func TimeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
