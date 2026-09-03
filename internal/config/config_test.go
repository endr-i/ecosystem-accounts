package config

import (
	"testing"
	"time"
)

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func baseEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":  "postgres://localhost/accounts",
		"AUTH_BASE_URL": "http://ecosystem-auth:8080",
	}
}

func TestLoadDerivesJWKSURLFromBaseURL(t *testing.T) {
	setEnv(t, baseEnv())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := "http://ecosystem-auth:8080/.well-known/jwks.json"
	if cfg.Auth.JWKSURL != want {
		t.Errorf("JWKSURL = %q, want %q", cfg.Auth.JWKSURL, want)
	}
	if cfg.Auth.Issuer != "ecosystem-auth" {
		t.Errorf("Issuer = %q, want ecosystem-auth", cfg.Auth.Issuer)
	}
	if cfg.Auth.JWKSRefreshInterval != 5*time.Minute {
		t.Errorf("refresh interval = %v, want 5m", cfg.Auth.JWKSRefreshInterval)
	}
	if cfg.Port != "8081" {
		t.Errorf("Port = %q, want 8081", cfg.Port)
	}
}

func TestLoadTrimsTrailingSlashOnBaseURL(t *testing.T) {
	env := baseEnv()
	env["AUTH_BASE_URL"] = "http://ecosystem-auth:8080/"
	setEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := "http://ecosystem-auth:8080/.well-known/jwks.json"
	if cfg.Auth.JWKSURL != want {
		t.Errorf("JWKSURL = %q, want %q", cfg.Auth.JWKSURL, want)
	}
}

func TestLoadExplicitJWKSURLWins(t *testing.T) {
	env := baseEnv()
	env["AUTH_JWKS_URL"] = "https://auth.example.com/keys"
	setEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.JWKSURL != "https://auth.example.com/keys" {
		t.Errorf("JWKSURL = %q", cfg.Auth.JWKSURL)
	}
}

func TestLoadJWKSURLWithoutBaseURL(t *testing.T) {
	setEnv(t, map[string]string{
		"DATABASE_URL":  "postgres://localhost/accounts",
		"AUTH_JWKS_URL": "http://ecosystem-auth:8080/.well-known/jwks.json",
	})
	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	env := baseEnv()
	env["AUTH_ISSUER"] = "https://auth.example.com"
	env["AUTH_JWKS_REFRESH_INTERVAL"] = "1m"
	env["AUTH_JWKS_TIMEOUT"] = "2s"
	env["AUTH_JWKS_STARTUP_TIMEOUT"] = "45s"
	env["PORT"] = "9000"
	setEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q", cfg.Auth.Issuer)
	}
	if cfg.Auth.JWKSRefreshInterval != time.Minute {
		t.Errorf("refresh = %v", cfg.Auth.JWKSRefreshInterval)
	}
	if cfg.Auth.JWKSTimeout != 2*time.Second {
		t.Errorf("timeout = %v", cfg.Auth.JWKSTimeout)
	}
	if cfg.Auth.StartupTimeout != 45*time.Second {
		t.Errorf("startup = %v", cfg.Auth.StartupTimeout)
	}
	if cfg.Port != "9000" {
		t.Errorf("Port = %q", cfg.Port)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]map[string]string{
		"missing database url": {"AUTH_BASE_URL": "http://auth:8080"},
		"missing auth address": {"DATABASE_URL": "postgres://localhost/accounts"},
		"bad jwks scheme": {
			"DATABASE_URL":  "postgres://localhost/accounts",
			"AUTH_JWKS_URL": "ftp://auth/keys",
		},
		"jwks url without host": {
			"DATABASE_URL":  "postgres://localhost/accounts",
			"AUTH_JWKS_URL": "/.well-known/jwks.json",
		},
		"bad base url": {
			"DATABASE_URL":  "postgres://localhost/accounts",
			"AUTH_BASE_URL": "ecosystem-auth:8080",
		},
	}
	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			for _, k := range []string{"DATABASE_URL", "AUTH_BASE_URL", "AUTH_JWKS_URL"} {
				t.Setenv(k, "")
			}
			setEnv(t, env)
			if _, err := Load(); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
