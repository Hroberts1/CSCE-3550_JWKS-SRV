package httpserver

import (
	"fmt"
	"os"
	"time"
)

const (
	defaultIssuer = "jwks-server"
	defaultJWTLifetime = "5m"
	defaultKeyRetain = "1h"
	defaultKeyLifetime = "10m"
)