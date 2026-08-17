package httpapi

import (
	"net/http"

	"github.com/company/iam/internal/application/ports/outbound"
)

// NewRouter wires the IAM's public HTTP surface (architecture plan §12):
// login/callback/token for the auth flow, JWKS for token verification,
// and a liveness probe.
func NewRouter(auth *AuthHandler, tokens outbound.TokenSigner) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", auth.Login)
	mux.HandleFunc("GET /callback", auth.Callback)
	mux.HandleFunc("POST /token", auth.Token)
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler(tokens))
	mux.HandleFunc("GET /healthz", healthHandler)

	return withMiddleware(mux)
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
