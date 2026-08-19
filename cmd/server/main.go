// Command server wires the IAM's ports to their concrete adapters and
// starts the public HTTP API (architecture plan §6). This is the only
// package allowed to import concrete adapters directly.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/haribabuk113/iam/internal/adapters/inbound/httpapi"
	"github.com/haribabuk113/iam/internal/adapters/outbound/jwtsign"
	"github.com/haribabuk113/iam/internal/adapters/outbound/memstore"
	"github.com/haribabuk113/iam/internal/adapters/outbound/postgres"
	"github.com/haribabuk113/iam/internal/adapters/outbound/supabase"
	"github.com/haribabuk113/iam/internal/adapters/outbound/ziplog"
	"github.com/haribabuk113/iam/internal/application/auth"
	"github.com/haribabuk113/iam/internal/config"
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

	// ziplog is the only concrete logger cmd/server knows about — swap it
	// for another outbound.Logger implementation here and nothing else in
	// the codebase changes.
	log, err := ziplog.New(cfg.Env)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer log.Sync()

	if err := postgres.Migrate(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	extraKeys, err := jwtsign.ParseExtraKeys([]byte(cfg.JWTJWKSExtraKeys))
	if err != nil {
		return err
	}
	signer, err := jwtsign.NewSigner(cfg.JWTPrivateKey, cfg.JWTIssuer, cfg.JWTKeyID, extraKeys)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	client, err := supabase.NewClient(cfg.SupabaseURL, cfg.SupabaseAnonKey, log)
	if err != nil {
		return fmt.Errorf("supabase client: %w", err)
	}
	authProvider := supabase.NewAdapter(client, cfg.CallbackURL)

	identities, err := postgres.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres identities: %w", err)
	}
	defer identities.Close()

	svc := auth.NewService(authProvider, identities, signer)

	// In-process — correct for exactly one iam-server replica, since the
	// OAuth callback (or the app's later /token call) must land on the
	// same process that started the flow. Swap for a shared backend (e.g.
	// Redis, behind the same outbound.LoginStateStore/ExchangeCodeStore
	// ports) if this ever needs to run more than one instance.
	states := memstore.NewLoginStates()
	exchanges := memstore.NewExchangeCodes()

	redirectOrigins := make(map[string][]string, len(cfg.AllowedApps))
	allowedOrigins := make(map[string]bool)
	for appID, app := range cfg.AllowedApps {
		redirectOrigins[appID] = app.RedirectOrigins
		for _, o := range app.RedirectOrigins {
			allowedOrigins[o] = true
		}
	}

	authHandler := httpapi.NewAuthHandler(svc, states, exchanges, redirectOrigins, log)
	router := httpapi.NewRouter(authHandler, signer, log, httpapi.RouterConfig{
		AllowedOrigins: allowedOrigins,
		RateLimitRPS:   cfg.RateLimitRPS,
		RateLimitBurst: cfg.RateLimitBurst,
	})

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("iam server starting", "addr", srv.Addr, "issuer", cfg.JWTIssuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serveErr:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}
