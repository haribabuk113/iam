package supabase

import (
	"context"
	"fmt"

	"github.com/supabase-community/auth-go/types"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
	"github.com/haribabuk113/iam/internal/domain/provider"
)

// Adapter implements outbound.AuthProviderPort against Supabase Auth
// (GoTrue). This is the ONLY place in the codebase that imports the
// Supabase client. Replacing Supabase later means writing a new adapter
// against this same interface — no other file changes.
type Adapter struct {
	client      *Client
	callbackURL string // IAM's own /callback URL, fixed, never per-application
}

func NewAdapter(client *Client, callbackURL string) *Adapter {
	return &Adapter{client: client, callbackURL: callbackURL}
}

func (a *Adapter) AuthorizeURL(p provider.Name, state, codeChallenge string) (string, error) {
	if !p.Valid() {
		return "", fmt.Errorf("supabase: unsupported provider %q", p)
	}
	redirectTo := a.callbackURL + "?iam_state=" + state
	return a.client.AuthorizeURL(string(p), redirectTo, codeChallenge), nil
}

func (a *Adapter) ExchangeCode(ctx context.Context, code, codeVerifier string) (outbound.ExternalIdentity, error) {
	sess, err := a.client.ExchangeCodeForSession(ctx, code, codeVerifier)
	if err != nil {
		return outbound.ExternalIdentity{}, err
	}
	return normalize(sess.User), nil
}

func (a *Adapter) SignUpWithPassword(ctx context.Context, email, password, fullName string) (outbound.ExternalIdentity, bool, error) {
	resp, err := a.client.SignUp(ctx, email, password, fullName)
	if err != nil {
		return outbound.ExternalIdentity{}, false, err
	}
	if resp.Session.AccessToken == "" {
		// Email confirmation required — Supabase has not issued a session,
		// so there is no verified identity to resolve yet.
		return outbound.ExternalIdentity{}, false, nil
	}
	return normalize(resp.User), true, nil
}

func (a *Adapter) SignInWithPassword(ctx context.Context, email, password string) (outbound.ExternalIdentity, error) {
	sess, err := a.client.SignInWithPassword(ctx, email, password)
	if err != nil {
		return outbound.ExternalIdentity{}, err
	}
	return normalize(sess.User), nil
}

// normalize maps Supabase's raw user shape onto the IAM's own
// ExternalIdentity. This is the single point where provider quirks
// (different metadata keys, missing fields) get absorbed — extend here,
// per provider, without touching any use case or handler.
func normalize(u types.User) outbound.ExternalIdentity {
	providerName, _ := u.AppMetadata["provider"].(string)

	fullName, _ := u.UserMetadata["full_name"].(string)
	if fullName == "" {
		fullName, _ = u.UserMetadata["name"].(string)
	}
	if fullName == "" {
		fullName = u.Email
	}

	return outbound.ExternalIdentity{
		Provider:       provider.Name(providerName),
		ProviderUserID: u.ID.String(),
		Email:          u.Email,
		FullName:       fullName,
		EmailVerified:  u.EmailConfirmedAt != nil,
	}
}
