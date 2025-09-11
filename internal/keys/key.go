package keys

import (
	"crypto/rsa"
	"time"
)

// RSA key pair w/ metadata
type Key struct {
	ID         string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// check if key expired
func (k *Key) IsExpired(now time.Time) bool {
	return now.After(k.ExpiresAt)
}

// convert to JWK format for JWKS
func (k *Key) ToJWK() map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": k.ID,
		"n":   encodeBase64URL(k.PublicKey.N.Bytes()),
		"e":   encodeBase64URL(intToBytes(k.PublicKey.E)),
		"alg": "RS256",
	}
}

// helper - convert int to bytes
func intToBytes(i int) []byte {
	bytes := make([]byte, 4)
	bytes[0] = byte(i >> 24)
	bytes[1] = byte(i >> 16)
	bytes[2] = byte(i >> 8)
	bytes[3] = byte(i)

	// remove leading zeros
	for len(bytes) > 1 && bytes[0] == 0 {
		bytes = bytes[1:]
	}

	return bytes
}

// helper - base64url encoding w/o padding
func encodeBase64URL(data []byte) string {
	const base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	encoded := ""
	for i := 0; i < len(data); i += 3 {
		chunk := 0
		chunkLen := 0

		for j := 0; j < 3 && i+j < len(data); j++ {
			chunk = (chunk << 8) | int(data[i+j])
			chunkLen++
		}

		chunk <<= (3 - chunkLen) * 8

		for j := 0; j < (chunkLen+1)*8/6; j++ {
			encoded += string(base64URL[(chunk>>(18-j*6))&63])
		}
	}

	return encoded
}
