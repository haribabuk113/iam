package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type AppConfig struct {
	RedirectOrigins []string `json:"redirect_origins"`
}

type Config struct {
	Port string
	Env  string // "production" or "development" — controls log format (see adapters/outbound/ziplog)

	SupabaseURL     string
	SupabaseAnonKey string
	CallbackURL     string // IAM's own /callback URL, e.g. https://auth.company.com/callback
	DatabaseURL     string // Supabase project's direct Postgres connection string

	JWTIssuer     string
	JWTKeyID      string
	JWTPrivateKey []byte
	// JWTJWKSExtraKeys is raw JSON — cmd/server hands it to
	// jwtsign.ParseExtraKeys, keeping config free of adapter imports.
	// Published in JWKS but never signed with — see jwtsign.NewSigner's
	// rotation doc.
	JWTJWKSExtraKeys string

	AllowedApps map[string]AppConfig

	// Per-IP token bucket guarding /login, /signup, /signin — see
	// adapters/inbound/httpapi rateLimit.
	RateLimitRPS   float64
	RateLimitBurst int
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:            getenv("IAM_PORT", "8080"),
		Env:             getenv("IAM_ENV", "development"),
		SupabaseURL:     os.Getenv("SUPABASE_URL"),
		SupabaseAnonKey: os.Getenv("SUPABASE_ANON_KEY"),
		// Must be this server's own /callback route — Supabase redirects
		// the browser back here, never straight to the application.
		CallbackURL: getenv("IAM_CALLBACK_URL", "http://localhost:8080/callback"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTIssuer:   getenv("JWT_ISSUER", "https://auth.company.com"),
		JWTKeyID:    getenv("JWT_KEY_ID", "iam-key-1"),
		// allow the key to be stored as a single env-var line with literal
		// \n sequences instead of real newlines (common in .env / compose)
		JWTPrivateKey:    []byte(strings.ReplaceAll(os.Getenv("JWT_PRIVATE_KEY"), `\n`, "\n")),
		JWTJWKSExtraKeys: getenv("JWT_JWKS_EXTRA_KEYS", "[]"),

		RateLimitRPS:   getenvFloat("IAM_RATE_LIMIT_RPS", 1),
		RateLimitBurst: getenvInt("IAM_RATE_LIMIT_BURST", 5),
	}

	if cfg.SupabaseURL == "" || cfg.SupabaseAnonKey == "" {
		return nil, fmt.Errorf("config: SUPABASE_URL and SUPABASE_ANON_KEY are required")
	}
	if cfg.CallbackURL == "" {
		return nil, fmt.Errorf("config: IAM_CALLBACK_URL is required")
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is required (Supabase project's direct Postgres connection string)")
	}
	if len(cfg.JWTPrivateKey) == 0 {
		return nil, fmt.Errorf("config: JWT_PRIVATE_KEY is required (see cmd/genkey)")
	}

	appsJSON := getenv("IAM_ALLOWED_APPS", "{}")
	if err := json.Unmarshal([]byte(appsJSON), &cfg.AllowedApps); err != nil {
		return nil, fmt.Errorf("config: invalid IAM_ALLOWED_APPS: %w", err)
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return i
}
