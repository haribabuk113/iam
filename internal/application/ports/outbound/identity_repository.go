package outbound

import (
	"context"

	"github.com/haribabuk113/iam/internal/domain/identity"
	"github.com/haribabuk113/iam/internal/domain/provider"
)

// IdentityRepository is the IAM's own system of record for identity
// (PRD §8) — deliberately separate from anything Supabase stores.
type IdentityRepository interface {
	FindByID(ctx context.Context, id identity.ClientEcosystemID) (*identity.Identity, error)
	FindByProviderUser(ctx context.Context, p provider.Name, providerUserID string) (*identity.Identity, error)
	FindByVerifiedEmail(ctx context.Context, email string) (*identity.Identity, error)
	Create(ctx context.Context, id identity.Identity) error
	LinkProvider(ctx context.Context, ecosystemID identity.ClientEcosystemID, p provider.Name, providerUserID string) error
}
