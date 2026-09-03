package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/endr-i/ecosystem-accounts/internal/authn"
)

const testKID = "key-test"

type testEnv struct {
	server *Server
	priv   *rsa.PrivateKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": testKID,
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)

	cache := authn.NewKeyCache(jwks.URL)
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh jwks: %v", err)
	}

	return &testEnv{
		server: NewServer(nil, authn.NewVerifier(cache, "ecosystem-auth"),
			slog.New(slog.NewTextHandler(io.Discard, nil))),
		priv: priv,
	}
}

func (e *testEnv) accessToken(t *testing.T, sub string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &jwt.RegisteredClaims{
		Subject:   sub,
		Issuer:    "ecosystem-auth",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	})
	token.Header["kid"] = testKID
	s, err := token.SignedString(e.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestRequireAuthRejectsMissingOrBadToken(t *testing.T) {
	env := newTestEnv(t)
	tests := map[string]string{
		"missing header": "",
		"not bearer":     "Basic abc",
		"empty bearer":   "Bearer ",
		"bad token":      "Bearer nonsense",
	}
	for name, header := range tests {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		env.server.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
	}
}

func TestRequireAuthPassesUserID(t *testing.T) {
	env := newTestEnv(t)
	var seen string
	h := env.server.requireAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = UserIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+env.accessToken(t, "user-42"))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen != "user-42" {
		t.Fatalf("user id = %q, want user-42", seen)
	}
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestEnv(t).server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
