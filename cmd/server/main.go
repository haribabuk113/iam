// Command server wires the IAM's ports to their concrete adapters and
// starts the public HTTP API (architecture plan §6). This is the only
// package allowed to import concrete adapters directly.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/company/iam/internal/adapters/inbound/httpapi"
	"github.com/company/iam/internal/adapters/outbound/jwtsign"
	"github.com/company/iam/internal/adapters/outbound/memoryrepo"
	"github.com/company/iam/internal/adapters/outbound/supabase"
	"github.com/company/iam/internal/application/auth"
	"github.com/company/iam/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	signer, err := jwtsign.NewSigner(cfg.JWTPrivateKey, cfg.JWTIssuer, cfg.JWTKeyID)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	client := supabase.NewClient(cfg.SupabaseURL, cfg.SupabaseAnonKey)
	authProvider := supabase.NewAdapter(client, cfg.CallbackURL)
	identities := memoryrepo.New()

	svc := auth.NewService(authProvider, identities, signer)

	states := httpapi.NewStateStore(5 * time.Minute)
	exchanges := httpapi.NewExchangeStore(30 * time.Second)

	redirectOrigins := make(map[string][]string, len(cfg.AllowedApps))
	for appID, app := range cfg.AllowedApps {
		redirectOrigins[appID] = app.RedirectOrigins
	}

	authHandler := httpapi.NewAuthHandler(svc, states, exchanges, redirectOrigins)
	router := httpapi.NewRouter(authHandler, signer)

	addr := ":" + cfg.Port
	slog.Info("iam server starting", "addr", addr, "issuer", cfg.JWTIssuer)
	return http.ListenAndServe(addr, router)
}
