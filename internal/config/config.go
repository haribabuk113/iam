package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type AppConfig struct {
	RedirectOrigins []string `json:"redirect_origins"`
}

type Config struct {
	Port string

	SupabaseURL     string
	SupabaseAnonKey string
	CallbackURL     string // IAM's own /callback URL, e.g. https://auth.company.com/callback

	JWTIssuer     string
	JWTKeyID      string
	JWTPrivateKey []byte

	EnabledProviders map[string]bool
	AllowedApps      map[string]AppConfig
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:            getenv("IAM_PORT", "8080"),
		SupabaseURL:     os.Getenv("SUPABASE_URL"),
		SupabaseAnonKey: os.Getenv("SUPABASE_ANON_KEY"),
		CallbackURL:     os.Getenv("IAM_CALLBACK_URL"),
		JWTIssuer:       getenv("JWT_ISSUER", "https://auth.company.com"),
		JWTKeyID:        getenv("JWT_KEY_ID", "iam-key-1"),
		// allow the key to be stored as a single env-var line with literal
		// \n sequences instead of real newlines (common in .env / compose)
		JWTPrivateKey: []byte(strings.ReplaceAll(os.Getenv("JWT_PRIVATE_KEY"), `\n`, "\n")),
	}

	if cfg.SupabaseURL == "" || cfg.SupabaseAnonKey == "" {
		return nil, fmt.Errorf("config: SUPABASE_URL and SUPABASE_ANON_KEY are required")
	}
	if cfg.CallbackURL == "" {
		return nil, fmt.Errorf("config: IAM_CALLBACK_URL is required")
	}
	if len(cfg.JWTPrivateKey) == 0 {
		return nil, fmt.Errorf("config: JWT_PRIVATE_KEY is required (see cmd/genkey)")
	}

	providers := getenv("PROVIDERS_ENABLED", "google")
	cfg.EnabledProviders = map[string]bool{}
	for _, p := range strings.Split(providers, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			cfg.EnabledProviders[p] = true
		}
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
