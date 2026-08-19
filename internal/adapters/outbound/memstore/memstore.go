// Package memstore is the only implementation of
// outbound.LoginStateStore / outbound.ExchangeCodeStore — an in-process
// map with lazy TTL expiry, no external dependency. Correct only for a
// single iam-server instance: the OAuth callback or the app's /token call
// has to land on the same process that wrote the entry. If this ever
// needs to run more than one instance, add a shared-backend
// implementation of the same two ports (see outbound.LoginStateStore's
// doc) rather than reaching for something process-local.
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

type loginEntry struct {
	value     outbound.LoginState
	expiresAt time.Time
}

// LoginStates implements outbound.LoginStateStore.
type LoginStates struct {
	mu   sync.Mutex
	data map[string]loginEntry
}

func NewLoginStates() *LoginStates {
	return &LoginStates{data: make(map[string]loginEntry)}
}

func (s *LoginStates) Put(_ context.Context, state string, v outbound.LoginState, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = loginEntry{value: v, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *LoginStates) Take(_ context.Context, state string) (outbound.LoginState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[state]
	delete(s.data, state)
	if !ok || time.Now().After(e.expiresAt) {
		return outbound.LoginState{}, false, nil
	}
	return e.value, true, nil
}

type exchangeValue struct {
	ecosystemID string
	appID       string
}

type exchangeEntry struct {
	value     exchangeValue
	expiresAt time.Time
}

// ExchangeCodes implements outbound.ExchangeCodeStore.
type ExchangeCodes struct {
	mu   sync.Mutex
	data map[string]exchangeEntry
}

func NewExchangeCodes() *ExchangeCodes {
	return &ExchangeCodes{data: make(map[string]exchangeEntry)}
}

func (s *ExchangeCodes) Put(_ context.Context, code, ecosystemID, appID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[code] = exchangeEntry{value: exchangeValue{ecosystemID: ecosystemID, appID: appID}, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *ExchangeCodes) Take(_ context.Context, code string) (string, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[code]
	delete(s.data, code)
	if !ok || time.Now().After(e.expiresAt) {
		return "", "", false, nil
	}
	return e.value.ecosystemID, e.value.appID, true, nil
}
