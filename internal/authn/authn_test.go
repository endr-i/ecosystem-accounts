package authn

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestVerifier(t *testing.T, srv *jwksServer) *Verifier {
	t.Helper()
	cache := NewKeyCache(srv.url())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return NewVerifier(cache, "ecosystem-auth")
}

func TestVerifyAccessToken(t *testing.T) {
	key := newTestKey(t, "key-2026-09")
	v := newTestVerifier(t, newJWKSServer(t, key))

	got, err := v.VerifyAccessToken(context.Background(), key.sign(t, claimsFor("user-1", time.Minute)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user-1" {
		t.Fatalf("subject = %q, want user-1", got)
	}
}

func TestVerifyAccessTokenRejects(t *testing.T) {
	key := newTestKey(t, "key-2026-09")
	other := newTestKey(t, "key-2026-09") // same kid, different private key
	unpublished := newTestKey(t, "key-unpublished")
	v := newTestVerifier(t, newJWKSServer(t, key))

	noKid := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsFor("user-1", time.Minute))
	noKidStr, err := noKid.SignedString(key.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tests := map[string]string{
		"wrong signing key": other.sign(t, claimsFor("user-1", time.Minute)),
		"unknown kid":       unpublished.sign(t, claimsFor("user-1", time.Minute)),
		"expired":           key.sign(t, claimsFor("user-1", -time.Minute)),
		"wrong issuer": key.sign(t, &jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "someone-else",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		}),
		"no subject": key.sign(t, &jwt.RegisteredClaims{
			Issuer:    "ecosystem-auth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		}),
		"missing kid header": noKidStr,
		"garbage":            "not-a-token",
	}
	for name, token := range tests {
		if _, err := v.VerifyAccessToken(context.Background(), token); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// An HS256 token signed with the RSA modulus is the classic algorithm
// confusion attack; WithValidMethods must reject it.
func TestVerifyAccessTokenRejectsAlgorithmConfusion(t *testing.T) {
	key := newTestKey(t, "key-2026-09")
	v := newTestVerifier(t, newJWKSServer(t, key))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsFor("user-1", time.Minute))
	token.Header["kid"] = key.kid
	forged, err := token.SignedString(key.priv.PublicKey.N.Bytes())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := v.VerifyAccessToken(context.Background(), forged); err == nil {
		t.Fatal("expected error for HS256 token")
	}
}

func TestVerifyAccessTokenRejectsNoneAlg(t *testing.T) {
	key := newTestKey(t, "key-2026-09")
	v := newTestVerifier(t, newJWKSServer(t, key))

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claimsFor("user-1", time.Minute))
	token.Header["kid"] = key.kid
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := v.VerifyAccessToken(context.Background(), unsigned); err == nil {
		t.Fatal("expected error for alg=none token")
	}
}

// An empty issuer disables the `iss` check.
func TestVerifyAccessTokenWithoutIssuerCheck(t *testing.T) {
	key := newTestKey(t, "key-2026-09")
	cache := NewKeyCache(newJWKSServer(t, key).url())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	v := NewVerifier(cache, "")

	token := key.sign(t, &jwt.RegisteredClaims{
		Subject:   "user-1",
		Issuer:    "anything",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	})
	if _, err := v.VerifyAccessToken(context.Background(), token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
