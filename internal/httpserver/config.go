package httpserver

import (
	"fmt"
	"os"
	"time"
)

const (
	defaultIssuer      = "jwks-server"
	defaultJWTLifetime = "5m"
	defaultKeyRetain   = "1h"
	defaultKeyLifetime = "10m"
)

type Config struct {
	KeyLifetime     time.Duration
	KeyRetainPeriod time.Duration
	JWTLifetime     time.Duration
	Issuer          string
}

func NewConfig() (*Config, error) {
	// setup the defaults
	issuer := defaultIssuer

	keyLifetime, err := time.ParseDuration(defaultKeyLifetime)
	if err != nil {
		return nil, fmt.Errorf("invalid defaultKeyLifetime: %w", err)
	}

	keyRetain, err := time.ParseDuration(defaultKeyRetain)
	if err != nil {
		return nil, fmt.Errorf("invalid defaultKeyRetain: %w", err)
	}

	jwtLifetime, err := time.ParseDuration(defaultJWTLifetime)
	if err != nil {
		return nil, fmt.Errorf("invalid defaultJWTLifetime: %w", err)
	}

	// override w/ env vars if set and valid
	overrides := map[string]struct {
		envKey string
		target *time.Duration
	}{
		"keyLifetime": {"KEY_LIFETIME", &keyLifetime},
		"keyRetain":   {"KEY_RETAIN", &keyRetain},
		"jwtLifetime": {"JWT_LIFETIME", &jwtLifetime},
	}

	// duration overrides
	for name, override := range overrides {
		if envVal := os.Getenv(override.envKey); envVal != "" {
			if parsed, parseErr := time.ParseDuration(envVal); parseErr == nil {
				*override.target = parsed
			} else {
				return nil, fmt.Errorf("invalid %s (%s): %w", override.envKey, name, parseErr)
			}
		}
	}

	// string override
	if envIssuer := os.Getenv("ISSUER"); envIssuer != "" {
		issuer = envIssuer
	}

	return &Config{
		KeyLifetime:     keyLifetime,
		KeyRetainPeriod: keyRetain,
		JWTLifetime:     jwtLifetime,
		Issuer:          issuer,
	}, nil
}
