// Package jwtsign issues and verifies the IAM's own JWTs. Applications
// never see a Supabase token — only tokens signed here, verifiable
// against JWKS() without any call back to the IAM (PRD §6, §19).
package jwtsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/company/iam/internal/application/ports/outbound"
)

const accessTokenTTL = 10 * time.Minute

type Signer struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	kid    string
	issuer string
}

// NewSigner loads an Ed25519 private key from a PKCS8 PEM block.
// Generate a dev key with: go run ./cmd/genkey
func NewSigner(privPEM []byte, issuer, kid string) (*Signer, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("jwtsign: invalid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtsign: parse key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("jwtsign: key is not Ed25519")
	}
	return &Signer{
		priv:   priv,
		pub:    priv.Public().(ed25519.PublicKey),
		kid:    kid,
		issuer: issuer,
	}, nil
}

type claims struct {
	Email  string `json:"email"`
	Name   string `json:"name"`
	Status string `json:"status"`
	jwt.RegisteredClaims
}

func (s *Signer) Sign(ic outbound.IdentityClaims) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(accessTokenTTL)

	c := claims{
		Email:  ic.Email,
		Name:   ic.FullName,
		Status: ic.Status,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   ic.EcosystemID,
			Audience:  jwt.ClaimStrings{"app-registry"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	tok.Header["kid"] = s.kid

	signed, err := tok.SignedString(s.priv)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

// JWKS publishes the public key so applications can verify tokens
// locally — the IAM is off the hot path of every authenticated request.
func (s *Signer) JWKS() ([]byte, error) {
	jwk := map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"use": "sig",
		"alg": "EdDSA",
		"kid": s.kid,
		"x":   base64.RawURLEncoding.EncodeToString(s.pub),
	}
	return json.Marshal(map[string]any{"keys": []any{jwk}})
}

// GenerateKeyPair is a dev/ops helper (see cmd/genkey) — not used at
// runtime by the server itself.
func GenerateKeyPair() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return privPEM, pubPEM, nil
}
