package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/endr-i/ecosystem-accounts/internal/authn"
)

var testSecret = []byte("test-secret")

func testServer() *Server {
	return NewServer(nil, authn.NewVerifier(testSecret, "ecosystem-auth"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func accessToken(t *testing.T, sub string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
		Subject:   sub,
		Issuer:    "ecosystem-auth",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}).SignedString(testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestRequireAuthRejectsMissingOrBadToken(t *testing.T) {
	s := testServer()
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
		s.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
	}
}

func TestRequireAuthPassesUserID(t *testing.T) {
	s := testServer()
	var seen string
	h := s.requireAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = UserIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken(t, "user-42"))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen != "user-42" {
		t.Fatalf("user id = %q, want user-42", seen)
	}
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer().Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
