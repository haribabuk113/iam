package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/haribabuk113/iam/internal/application/ports/outbound"
)

// NewRouter wires the IAM's public HTTP surface (architecture plan §12):
// login/callback/token/signup/signin for the auth flow, JWKS for token
// verification, and a liveness probe. Built on chi rather than the stdlib
// mux — chi's routing tree and middleware/subrouter model is the standard
// choice once a Go HTTP API needs to grow (more routes, per-route
// middleware like timeouts or rate limits) without becoming unwieldy.
func NewRouter(auth *AuthHandler, tokens outbound.TokenSigner, log outbound.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(requestID, recoverer(log), requestLogger(log))

	r.Get("/login", auth.Login)
	r.Get("/callback", auth.Callback)
	r.Post("/token", auth.Token)
	r.Post("/signup", auth.SignUp)
	r.Post("/signin", auth.SignIn)
	r.Get("/.well-known/jwks.json", jwksHandler(tokens))
	r.Get("/healthz", healthHandler)

	return r
}

func jwksHandler(tokens outbound.TokenSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, err := tokens.JWKS()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwks_unavailable"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwks)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
