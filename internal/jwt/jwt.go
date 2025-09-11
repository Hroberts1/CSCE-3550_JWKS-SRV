package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// JWT header
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// JWT payload
type Payload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

// create JWT w/ RSA key
func CreateJWT(privKey *rsa.PrivateKey, kid, issuer string, expiry time.Duration) (string, error) {
	now := time.Now()

	// header
	header := Header{
		Alg: "RS256",
		Typ: "JWT",
		Kid: kid,
	}

	// payload
	payload := Payload{
		Iss: issuer,
		Sub: "user123", // mock user
		Aud: "jwks-client",
		Iat: now.Unix(),
		Exp: now.Add(expiry).Unix(),
	}

	// encode header and payload
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("header marshal error: %w", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("payload marshal error: %w", err)
	}

	headerB64 := encodeBase64URL(headerBytes)
	payloadB64 := encodeBase64URL(payloadBytes)

	// sign
	message := headerB64 + "." + payloadB64
	signature, err := signRS256([]byte(message), privKey)
	if err != nil {
		return "", fmt.Errorf("signing error: %w", err)
	}

	signatureB64 := encodeBase64URL(signature)

	return message + "." + signatureB64, nil
}

// sign w/ RS256
func signRS256(data []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
}

// base64url encode
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
