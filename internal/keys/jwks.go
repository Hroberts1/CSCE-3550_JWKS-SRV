package keys

// JWKS response format
type JWKS struct {
	Keys []map[string]interface{} `json:"keys"`
}

// get JWKS format - only valid keys
func (m *Manager) GetJWKS() (*JWKS, error) {
	validKeys := m.GetValidKeys()

	jwks := &JWKS{
		Keys: make([]map[string]interface{}, 0, len(validKeys)),
	}

	for _, key := range validKeys {
		jwks.Keys = append(jwks.Keys, key.ToJWK())
	}

	return jwks, nil
}
