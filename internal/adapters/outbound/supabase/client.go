// Package supabase is the ONLY package in the codebase permitted to know
// Supabase's wire format. Everything above it talks in terms of
// outbound.AuthProviderPort / outbound.ExternalIdentity (see adapter.go).
package supabase

import (
	"context"
	"fmt"
	"net/url"

	authgo "github.com/supabase-community/auth-go"
	"github.com/supabase-community/auth-go/types"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

// Client wraps the official Supabase Auth Go client
// (supabase-community/auth-go) directly — not the supabase-go umbrella
// package, whose Storage/Functions/Postgrest sub-clients this service has
// no use for and never will per the PRD (§16: the IAM is responsible only
// for identity, authentication, session management, and identity provider
// integration). auth-go also ships real tagged releases, unlike
// supabase-go's tagged release at the time of writing (see CLAUDE.md).
type Client struct {
	baseURL string // e.g. http://localhost:9999 (self-hosted GoTrue, no Kong prefix)
	auth    authgo.Client
	log     outbound.Logger
}

// anonKey is sent as the apiKey header on every request but self-hosted
// GoTrue (no Kong gateway in front) never checks it — any non-empty
// placeholder works. Kept required so nothing silently breaks if a Kong
// layer is added later and starts enforcing it.
func NewClient(baseURL, anonKey string, log outbound.Logger) (*Client, error) {
	if baseURL == "" || anonKey == "" {
		return nil, fmt.Errorf("supabase: baseURL and anonKey are required")
	}
	auth := authgo.New(baseURL, anonKey).WithCustomAuthURL(baseURL)
	return &Client{baseURL: baseURL, auth: auth, log: log}, nil
}

// AuthorizeURL builds the GoTrue /authorize URL that starts the OAuth
// dance with the given provider. redirectTo must be the IAM's own
// callback URL (carrying our opaque iam_state param) — never an
// application URL. Supabase performs the provider round trip and
// redirects the browser back to exactly this URL with ?code=... appended.
//
// Built by hand rather than through the client library's Auth.Authorize:
// that call performs its own server-side round trip to Supabase and
// generates its own PKCE verifier, which doesn't fit the IAM's flow —
// the verifier here is generated at /login time (httpapi/pkce.go) and
// must survive, keyed by state, until the browser's callback arrives.
func (c *Client) AuthorizeURL(provider, redirectTo, codeChallenge string) string {
	v := url.Values{}
	v.Set("provider", provider)
	v.Set("redirect_to", redirectTo)
	v.Set("code_challenge", codeChallenge)
	v.Set("code_challenge_method", "s256")
	return fmt.Sprintf("%s/authorize?%s", c.baseURL, v.Encode())
}

// ExchangeCodeForSession completes the PKCE flow: trades the
// authorization code from the callback, plus the verifier generated at
// /login time, for a Supabase session. The resulting AccessToken is
// Supabase's own JWT — used ONLY to identify the user (see normalize()
// in adapter.go) and is never forwarded to applications. The IAM mints
// its own JWT afterward (see adapters/outbound/jwtsign).
func (c *Client) ExchangeCodeForSession(ctx context.Context, code, codeVerifier string) (*types.Session, error) {
	resp, err := c.auth.Token(types.TokenRequest{
		GrantType:    "pkce",
		Code:         code,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		return nil, fmt.Errorf("supabase: exchange code: %w", err)
	}
	return &resp.Session, nil
}

// SignUp registers a new email+password user. If the Supabase project
// requires email confirmation (the default), no session comes back yet —
// resp.Session.AccessToken is empty until the user clicks the
// confirmation link and Supabase issues one.
func (c *Client) SignUp(ctx context.Context, email, password, fullName string) (*types.SignupResponse, error) {
	resp, err := c.auth.Signup(types.SignupRequest{
		Email:    email,
		Password: password,
		Data:     map[string]any{"full_name": fullName},
	})
	c.log.Info("supabase signup response", "resp", resp, "err", err)
	if err != nil {
		return nil, fmt.Errorf("supabase: signup: %w", err)
	}
	return resp, nil
}

// SignInWithPassword authenticates an existing email+password user.
func (c *Client) SignInWithPassword(ctx context.Context, email, password string) (*types.Session, error) {
	resp, err := c.auth.SignInWithEmailPassword(email, password)
	if err != nil {
		return nil, fmt.Errorf("supabase: sign in: %w", err)
	}
	return &resp.Session, nil
}
