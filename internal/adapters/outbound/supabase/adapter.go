package supabase

import (
	"context"
	"fmt"

	"github.com/company/iam/internal/application/ports/outbound"
	"github.com/company/iam/internal/domain/provider"
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

// normalize maps Supabase's raw user shape onto the IAM's own
// ExternalIdentity. This is the single point where provider quirks
// (different metadata keys, missing fields) get absorbed — extend here,
// per provider, without touching any use case or handler.
func normalize(u User) outbound.ExternalIdentity {
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
		ProviderUserID: u.ID,
		Email:          u.Email,
		FullName:       fullName,
		EmailVerified:  u.EmailConfirmedAt != nil,
	}
}
