package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKey is an RSA key plus the kid it is published under.
type testKey struct {
	kid  string
	priv *rsa.PrivateKey
}

func newTestKey(t *testing.T, kid string) testKey {
	t.Helper()
	// 1024 bits keeps tests fast; production keys are 2048 (see auth's keys.KeySize).
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testKey{kid: kid, priv: priv}
}

func (k testKey) jwk() jwk {
	pub := &k.priv.PublicKey
	return jwk{
		Kid: k.kid,
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (k testKey) sign(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = k.kid
	s, err := token.SignedString(k.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func claimsFor(sub string, ttl time.Duration) *jwt.RegisteredClaims {
	now := time.Now()
	return &jwt.RegisteredClaims{
		Subject:   sub,
		Issuer:    "ecosystem-auth",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
}

// jwksServer serves a mutable key set and counts requests.
type jwksServer struct {
	*httptest.Server
	calls atomic.Int64
	keys  atomic.Pointer[[]jwk]
	// status, when non-zero, is returned instead of the document.
	status atomic.Int64
}

func newJWKSServer(t *testing.T, keys ...testKey) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.setKeys(keys...)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.calls.Add(1)
		if code := s.status.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: *s.keys.Load()})
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) setKeys(keys ...testKey) {
	jwks := make([]jwk, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, k.jwk())
	}
	s.keys.Store(&jwks)
}

func (s *jwksServer) url() string { return s.Server.URL + "/.well-known/jwks.json" }
