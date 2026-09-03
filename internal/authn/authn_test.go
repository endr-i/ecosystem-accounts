package authn

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func sign(t *testing.T, secret []byte, claims jwt.Claims, method jwt.SigningMethod) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func validClaims(sub string, exp time.Duration) *jwt.RegisteredClaims {
	now := time.Now()
	return &jwt.RegisteredClaims{
		Subject:   sub,
		Issuer:    "ecosystem-auth",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(exp)),
	}
}

func TestVerifyAccessToken(t *testing.T) {
	secret := []byte("test-secret")
	v := NewVerifier(secret, "ecosystem-auth")

	token := sign(t, secret, validClaims("user-1", time.Minute), jwt.SigningMethodHS256)
	got, err := v.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user-1" {
		t.Fatalf("subject = %q, want user-1", got)
	}
}

func TestVerifyAccessTokenRejects(t *testing.T) {
	secret := []byte("test-secret")
	v := NewVerifier(secret, "ecosystem-auth")

	tests := map[string]string{
		"wrong secret": sign(t, []byte("other"), validClaims("user-1", time.Minute), jwt.SigningMethodHS256),
		"expired":      sign(t, secret, validClaims("user-1", -time.Minute), jwt.SigningMethodHS256),
		"wrong issuer": sign(t, secret, &jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "someone-else",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		}, jwt.SigningMethodHS256),
		"no subject": sign(t, secret, &jwt.RegisteredClaims{
			Issuer:    "ecosystem-auth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		}, jwt.SigningMethodHS256),
		"garbage": "not-a-token",
	}
	for name, token := range tests {
		if _, err := v.VerifyAccessToken(token); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestVerifyAccessTokenRejectsNoneAlg(t *testing.T) {
	v := NewVerifier([]byte("test-secret"), "ecosystem-auth")
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims("user-1", time.Minute)).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := v.VerifyAccessToken(unsigned); err == nil {
		t.Fatal("expected error for alg=none token")
	}
}
