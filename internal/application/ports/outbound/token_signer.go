package outbound

import "time"

// IdentityClaims is the minimal, identity-only claim set the IAM will
// ever put in a token (PRD §8) — no roles, no permissions, no business data.
type IdentityClaims struct {
	EcosystemID string
	Email       string
	FullName    string
	Status      string
}

// TokenSigner mints and publishes verification material for the IAM's own
// JWTs. Applications verify locally via JWKS() — the IAM is never on the
// hot path of an authenticated request, only of a login.
type TokenSigner interface {
	Sign(claims IdentityClaims) (token string, expiresAt time.Time, err error)
	JWKS() ([]byte, error)
}
