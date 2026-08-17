// Package memoryrepo is an in-memory IdentityRepository for local
// development and the first runnable slice of the service only.
// Replace with a Postgres adapter (internal/adapters/outbound/postgres,
// see architecture plan §13) before any real deployment — nothing here
// survives a restart and it is not safe across multiple replicas.
package memoryrepo

import (
	"context"
	"sync"

	"github.com/company/iam/internal/domain/identity"
	"github.com/company/iam/internal/domain/provider"
)

type Repo struct {
	mu         sync.RWMutex
	byID       map[identity.ClientEcosystemID]*identity.Identity
	byEmail    map[string]identity.ClientEcosystemID
	byProvider map[string]identity.ClientEcosystemID // key: provider|providerUserID
}

func New() *Repo {
	return &Repo{
		byID:       make(map[identity.ClientEcosystemID]*identity.Identity),
		byEmail:    make(map[string]identity.ClientEcosystemID),
		byProvider: make(map[string]identity.ClientEcosystemID),
	}
}

func providerKey(p provider.Name, providerUserID string) string {
	return string(p) + "|" + providerUserID
}

func (r *Repo) FindByID(ctx context.Context, id identity.ClientEcosystemID) (*identity.Identity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	found, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *found
	return &cp, nil
}

func (r *Repo) FindByProviderUser(ctx context.Context, p provider.Name, providerUserID string) (*identity.Identity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byProvider[providerKey(p, providerUserID)]
	if !ok {
		return nil, nil
	}
	cp := *r.byID[id]
	return &cp, nil
}

func (r *Repo) FindByVerifiedEmail(ctx context.Context, email string) (*identity.Identity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byEmail[identity.NormalizeEmail(email)]
	if !ok {
		return nil, nil
	}
	cp := *r.byID[id]
	return &cp, nil
}

func (r *Repo) Create(ctx context.Context, id identity.Identity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id.Email = identity.NormalizeEmail(id.Email)
	stored := id
	r.byID[id.ID] = &stored
	r.byEmail[id.Email] = id.ID
	return nil
}

func (r *Repo) LinkProvider(ctx context.Context, ecosystemID identity.ClientEcosystemID, p provider.Name, providerUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byProvider[providerKey(p, providerUserID)] = ecosystemID
	return nil
}
