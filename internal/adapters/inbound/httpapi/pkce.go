package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newPKCEVerifier returns a code_verifier per RFC 7636 (43-128 chars).
func newPKCEVerifier() (string, error) {
	return randomURLSafe(32) // 32 random bytes -> 43 base64url chars
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newState() (string, error) {
	return randomURLSafe(24)
}

func newExchangeCode() (string, error) {
	return randomURLSafe(24)
}
