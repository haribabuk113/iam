package httpapi

import (
	"sync"
	"time"

	"github.com/haribabuk113/iam/internal/domain/provider"
)

type loginState struct {
	CodeVerifier string
	Provider     provider.Name
	ReturnTo     string
	AppID        string
	ExpiresAt    time.Time
}

// StateStore holds short-lived, single-use login-flow state (PKCE
// verifier, return_to, app_id) keyed by the opaque `state` value.
// In-memory + TTL is sufficient for a single replica; swap for Redis
// (architecture plan §10) once the IAM runs more than one pod — the
// callback can land on a different pod than the one that started the
// login.
type StateStore struct {
	mu   sync.Mutex
	data map[string]loginState
	ttl  time.Duration
}

func NewStateStore(ttl time.Duration) *StateStore {
	return &StateStore{data: make(map[string]loginState), ttl: ttl}
}

func (s *StateStore) Put(state string, v loginState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.ExpiresAt = time.Now().Add(s.ttl)
	s.data[state] = v
}

// Take returns and deletes the entry (single use) if present and unexpired.
func (s *StateStore) Take(state string) (loginState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[state]
	delete(s.data, state)
	if !ok || time.Now().After(v.ExpiresAt) {
		return loginState{}, false
	}
	return v, true
}

// ExchangeStore holds single-use, short-TTL codes for the IAM->App leg —
// the browser is handed this opaque code, never a JWT, in the redirect
// URL (avoids putting tokens in browser history / referrer / server logs).
type ExchangeStore struct {
	mu   sync.Mutex
	data map[string]exchangeEntry
	ttl  time.Duration
}

type exchangeEntry struct {
	EcosystemID string
	ExpiresAt   time.Time
}

func NewExchangeStore(ttl time.Duration) *ExchangeStore {
	return &ExchangeStore{data: make(map[string]exchangeEntry), ttl: ttl}
}

func (s *ExchangeStore) Put(code, ecosystemID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[code] = exchangeEntry{EcosystemID: ecosystemID, ExpiresAt: time.Now().Add(s.ttl)}
}

func (s *ExchangeStore) Take(code string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[code]
	delete(s.data, code)
	if !ok || time.Now().After(v.ExpiresAt) {
		return "", false
	}
	return v.EcosystemID, true
}
