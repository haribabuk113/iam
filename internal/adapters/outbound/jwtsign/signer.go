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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

const accessTokenTTL = 10 * time.Minute

// ExtraKey is a public key published in JWKS alongside the signing key,
// but never used to sign — see ParseExtraKeys and the rotation procedure
// documented there.
type ExtraKey struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
}

type extraPub struct {
	kid string
	pub ed25519.PublicKey
}

type Signer struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	kid    string
	issuer string
	extra  []extraPub
}

// NewSigner loads an Ed25519 private key from a PKCS8 PEM block and
// signs with it under kid. extra are additional public keys published in
// JWKS but never used to sign — see ParseExtraKeys.
//
// Key rotation, since this Signer only ever holds one signing key: this
// service is itself a JWKS issuer for downstream apps, so a bare key swap
// is a hard cutover — every token signed under the old key becomes
// unverifiable the instant the new key deploys, and any app that cached
// the old JWKS response has no overlap window to pick up the new one
// (mirrors the caching problem Supabase's own JWT docs describe for their
// managed JWKS, recommending >=20 minutes of dual-key overlap). To
// rotate safely:
//  1. go run ./cmd/genkey to generate the next keypair.
//  2. Deploy with JWT_JWKS_EXTRA_KEYS containing the NEW public key
//     (a new kid) while still signing with the OLD private key. JWKS now
//     publishes both; consuming apps refresh their cache and pick up the
//     new key.
//  3. Wait at least accessTokenTTL (10 minutes) plus a safety margin.
//  4. Deploy with JWT_PRIVATE_KEY/JWT_KEY_ID switched to the new key, and
//     move the OLD public key into JWT_JWKS_EXTRA_KEYS instead — so
//     already-issued, not-yet-expired tokens signed under it still verify.
//  5. After accessTokenTTL has passed again, drop the old key from
//     JWT_JWKS_EXTRA_KEYS entirely.
func NewSigner(privPEM []byte, issuer, kid string, extra []ExtraKey) (*Signer, error) {
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

	extraPubs, err := parseExtraKeys(extra)
	if err != nil {
		return nil, err
	}

	return &Signer{
		priv:   priv,
		pub:    priv.Public().(ed25519.PublicKey),
		kid:    kid,
		issuer: issuer,
		extra:  extraPubs,
	}, nil
}

// ParseExtraKeys parses the JSON form of JWT_JWKS_EXTRA_KEYS
// (`[{"kid":"...","public_key":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}]`)
// — a raw env var, not yet resolved to ed25519 keys. Kept separate from
// NewSigner so config-layer errors (bad JSON) surface distinctly from
// key-parsing errors.
func ParseExtraKeys(raw []byte) ([]ExtraKey, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var keys []ExtraKey
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("jwtsign: invalid JWT_JWKS_EXTRA_KEYS: %w", err)
	}
	return keys, nil
}

func parseExtraKeys(in []ExtraKey) ([]extraPub, error) {
	out := make([]extraPub, 0, len(in))
	for _, k := range in {
		pemBytes := []byte(strings.ReplaceAll(k.PublicKey, `\n`, "\n"))
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("jwtsign: invalid PEM for extra key %q", k.KID)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("jwtsign: parse extra key %q: %w", k.KID, err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwtsign: extra key %q is not Ed25519", k.KID)
		}
		out = append(out, extraPub{kid: k.KID, pub: edPub})
	}
	return out, nil
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

// JWKS publishes the signing key plus any extra (rotation) keys, so
// applications can verify tokens locally — the IAM is off the hot path of
// every authenticated request. See NewSigner's doc for the rotation
// procedure this supports.
func (s *Signer) JWKS() ([]byte, error) {
	keys := make([]any, 0, 1+len(s.extra))
	keys = append(keys, jwkFor(s.kid, s.pub))
	for _, e := range s.extra {
		keys = append(keys, jwkFor(e.kid, e.pub))
	}
	return json.Marshal(map[string]any{"keys": keys})
}

func jwkFor(kid string, pub ed25519.PublicKey) map[string]string {
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"use": "sig",
		"alg": "EdDSA",
		"kid": kid,
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
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
