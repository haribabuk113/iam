// Package postgres is the durable IdentityRepository adapter (architecture
// plan §13), replacing the dev-only memoryrepo. Schema is applied
// automatically at startup via Migrate() (see migrate.go) — no manual step.
package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/haribabuk113/iam/internal/domain/identity"
	"github.com/haribabuk113/iam/internal/domain/provider"
)

type Repo struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, connString string) (*Repo, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Repo{pool: pool}, nil
}

func (r *Repo) Close() {
	r.pool.Close()
}

func (r *Repo) FindByID(ctx context.Context, id identity.ClientEcosystemID) (*identity.Identity, error) {
	return r.scanOne(ctx, `
		SELECT id, full_name, email, primary_provider, status, created_at
		FROM identities WHERE id = $1`, id)
}

func (r *Repo) FindByProviderUser(ctx context.Context, p provider.Name, providerUserID string) (*identity.Identity, error) {
	return r.scanOne(ctx, `
		SELECT i.id, i.full_name, i.email, i.primary_provider, i.status, i.created_at
		FROM identities i
		JOIN identity_providers ip ON ip.ecosystem_id = i.id
		WHERE ip.provider = $1 AND ip.provider_user_id = $2`, p, providerUserID)
}

func (r *Repo) FindByVerifiedEmail(ctx context.Context, email string) (*identity.Identity, error) {
	return r.scanOne(ctx, `
		SELECT id, full_name, email, primary_provider, status, created_at
		FROM identities WHERE email = $1`, identity.NormalizeEmail(email))
}

func (r *Repo) Create(ctx context.Context, id identity.Identity) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO identities (id, full_name, email, primary_provider, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id.ID, id.FullName, identity.NormalizeEmail(id.Email), id.PrimaryProvider, id.Status, id.CreatedAt)
	return err
}

func (r *Repo) LinkProvider(ctx context.Context, ecosystemID identity.ClientEcosystemID, p provider.Name, providerUserID string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO identity_providers (provider, provider_user_id, ecosystem_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, provider_user_id) DO NOTHING`,
		p, providerUserID, ecosystemID)
	return err
}

func (r *Repo) scanOne(ctx context.Context, query string, args ...any) (*identity.Identity, error) {
	var id identity.Identity
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&id.ID, &id.FullName, &id.Email, &id.PrimaryProvider, &id.Status, &id.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}
