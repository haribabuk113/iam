// Package supabase is the ONLY package in the codebase permitted to know
// Supabase's wire format. Everything above it talks in terms of
// outbound.AuthProviderPort / outbound.ExternalIdentity (see adapter.go).
package supabase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is a thin wrapper around Supabase's GoTrue REST API.
type Client struct {
	baseURL    string // e.g. https://xxxx.supabase.co
	anonKey    string
	httpClient *http.Client
}

func NewClient(baseURL, anonKey string) *Client {
	return &Client{
		baseURL:    baseURL,
		anonKey:    anonKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthorizeURL builds the GoTrue /authorize URL that starts the OAuth
// dance with the given provider. redirectTo must be the IAM's own
// callback URL (carrying our opaque iam_state param) — never an
// application URL. Supabase performs the provider round trip and
// redirects the browser back to exactly this URL with ?code=... appended.
func (c *Client) AuthorizeURL(provider, redirectTo, codeChallenge string) string {
	v := url.Values{}
	v.Set("provider", provider)
	v.Set("redirect_to", redirectTo)
	v.Set("code_challenge", codeChallenge)
	v.Set("code_challenge_method", "s256")
	return fmt.Sprintf("%s/auth/v1/authorize?%s", c.baseURL, v.Encode())
}

type Session struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	User         User   `json:"user"`
}

type User struct {
	ID               string         `json:"id"`
	Aud              string         `json:"aud"`
	Role             string         `json:"role"`
	Email            string         `json:"email"`
	EmailConfirmedAt *string        `json:"email_confirmed_at"`
	AppMetadata      map[string]any `json:"app_metadata"`
	UserMetadata     map[string]any `json:"user_metadata"`
	CreatedAt        string         `json:"created_at"`
}

type gotrueError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Msg              string `json:"msg"`
}

// ExchangeCodeForSession completes the PKCE flow: trades the
// authorization code from the callback, plus the verifier generated at
// /login time, for a Supabase session. The resulting AccessToken is
// Supabase's own JWT — used ONLY to identify the user (see normalize()
// in adapter.go) and is never forwarded to applications. The IAM mints
// its own JWT afterward (see adapters/outbound/jwtsign).
func (c *Client) ExchangeCodeForSession(ctx context.Context, code, codeVerifier string) (*Session, error) {
	body, _ := json.Marshal(map[string]string{
		"auth_code":     code,
		"code_verifier": codeVerifier,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/auth/v1/token?grant_type=pkce", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", c.anonKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("supabase: exchange code: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var gerr gotrueError
		_ = json.Unmarshal(raw, &gerr)
		return nil, fmt.Errorf("supabase: exchange code failed (%d): %s %s", resp.StatusCode, gerr.Error, gerr.ErrorDescription)
	}

	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, fmt.Errorf("supabase: decode session: %w", err)
	}
	return &sess, nil
}

// GetUser fetches the full user object for a Supabase access token. Not
// needed for the login flow itself (ExchangeCodeForSession already
// returns the user) but kept for future session-refresh validation.
func (c *Client) GetUser(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/auth/v1/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("apikey", c.anonKey)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("supabase: get user failed (%d): %s", resp.StatusCode, raw)
	}
	var u User
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}
