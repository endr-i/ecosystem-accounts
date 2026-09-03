package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// jwksPath is the well-known location of the auth service's key set.
const jwksPath = "/.well-known/jwks.json"

type Config struct {
	Port        string
	DatabaseURL string
	Auth        AuthConfig
}

// AuthConfig describes how to reach ecosystem-auth and validate its tokens.
type AuthConfig struct {
	// Issuer is the expected `iss` claim. Note this is the auth service's
	// identifier, not its address; an empty value disables the check.
	Issuer string
	// JWKSURL is where public signing keys are published.
	JWKSURL string
	// JWKSRefreshInterval controls how often cached keys are refreshed.
	JWKSRefreshInterval time.Duration
	// JWKSTimeout bounds a single JWKS HTTP request.
	JWKSTimeout time.Duration
	// StartupTimeout bounds the retrying initial key fetch.
	StartupTimeout time.Duration
}

func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	authCfg, err := loadAuth()
	if err != nil {
		return nil, err
	}

	return &Config{
		Port:        getEnv("PORT", "8081"),
		DatabaseURL: dbURL,
		Auth:        *authCfg,
	}, nil
}

func loadAuth() (*AuthConfig, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_BASE_URL")), "/")
	jwksURL := strings.TrimSpace(os.Getenv("AUTH_JWKS_URL"))

	if jwksURL == "" {
		if baseURL == "" {
			return nil, fmt.Errorf("AUTH_JWKS_URL or AUTH_BASE_URL is required")
		}
		jwksURL = baseURL + jwksPath
	}
	if err := validateHTTPURL("AUTH_JWKS_URL", jwksURL); err != nil {
		return nil, err
	}
	if baseURL != "" {
		if err := validateHTTPURL("AUTH_BASE_URL", baseURL); err != nil {
			return nil, err
		}
	}

	return &AuthConfig{
		Issuer:              getEnv("AUTH_ISSUER", "ecosystem-auth"),
		JWKSURL:             jwksURL,
		JWKSRefreshInterval: getDuration("AUTH_JWKS_REFRESH_INTERVAL", 5*time.Minute),
		JWKSTimeout:         getDuration("AUTH_JWKS_TIMEOUT", 5*time.Second),
		StartupTimeout:      getDuration("AUTH_JWKS_STARTUP_TIMEOUT", 30*time.Second),
	}, nil
}

func validateHTTPURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s must be an http(s) URL, got %q", name, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%s must include a host, got %q", name, raw)
	}
	return nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
