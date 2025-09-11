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
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	
	if len(data) == 0 {
		return ""
	}
	
	encoded := ""
	
	// process 3 bytes at a time
	for i := 0; i < len(data); i += 3 {
		b1, b2, b3 := data[i], byte(0), byte(0)
		if i+1 < len(data) {
			b2 = data[i+1]
		}
		if i+2 < len(data) {
			b3 = data[i+2]
		}
		
		// combine 3 bytes into 24 bits
		combined := (uint32(b1) << 16) | (uint32(b2) << 8) | uint32(b3)
		
		// extract 6-bit chunks
		encoded += string(alphabet[(combined>>18)&0x3F])
		encoded += string(alphabet[(combined>>12)&0x3F])
		
		if i+1 < len(data) {
			encoded += string(alphabet[(combined>>6)&0x3F])
		}
		if i+2 < len(data) {
			encoded += string(alphabet[combined&0x3F])
		}
	}
	
	return encoded
}
