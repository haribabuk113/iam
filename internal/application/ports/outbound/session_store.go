package outbound

import (
	"context"
	"time"

	"github.com/haribabuk113/iam/internal/domain/provider"
)

// LoginState is the short-lived, single-use data an in-flight OAuth login
// attempt needs to survive from /login to /callback: the PKCE verifier,
// which provider was chosen, and where to send the browser back to.
type LoginState struct {
	CodeVerifier string
	Provider     provider.Name
	ReturnTo     string
	AppID        string
}

// LoginStateStore holds LoginState keyed by the opaque `state` value for
// the login flow's TTL. The callback can land on a different replica than
// the one that started the login, so this only works correctly with
// exactly one iam-server instance — see adapters/outbound/memstore, the
// only implementation today.
type LoginStateStore interface {
	Put(ctx context.Context, state string, v LoginState, ttl time.Duration) error
	// Take returns the stored value and deletes it (single use). ok is
	// false if the state was never stored, already consumed, or expired.
	Take(ctx context.Context, state string) (v LoginState, ok bool, err error)
}

// ExchangeCodeStore holds the opaque IAM->App exchange code minted at
// /callback until the application's backend redeems it at /token — the
// browser is handed this code, never a JWT, so tokens never sit in
// browser history/referrer/server logs. Bound to the app_id it was issued
// for, so possession of the code alone is not sufficient to redeem it —
// the redeeming caller must also know which app it was issued to.
type ExchangeCodeStore interface {
	Put(ctx context.Context, code, ecosystemID, appID string, ttl time.Duration) error
	// Take returns the stored value and deletes it (single use).
	Take(ctx context.Context, code string) (ecosystemID, appID string, ok bool, err error)
}
