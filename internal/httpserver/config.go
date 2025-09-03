package httpserver

import (
	"fmt"
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

	// OverRide w/ env vars IF set AND valid

	return &Config{
		KeyLifetime:     keyLifetime,
		KeyRetainPeriod: keyRetain,
		JWTLifetime:     jwtLifetime,
		Issuer:          issuer,
	}, nil
}
