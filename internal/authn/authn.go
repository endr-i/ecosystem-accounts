// Package authn verifies access tokens issued by ecosystem-auth.
//
// Tokens are RS256 JWTs whose subject is the user ID and whose header carries
// the `kid` of the signing key. Public keys are fetched from the auth service's
// JWKS endpoint and cached, so verification needs no per-request network call.
package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid or expired token")

type Verifier struct {
	keys   *KeyCache
	issuer string
}

func NewVerifier(keys *KeyCache, issuer string) *Verifier {
	return &Verifier{keys: keys, issuer: issuer}
}

// VerifyAccessToken validates the JWT and returns the user ID (subject).
func (v *Verifier) VerifyAccessToken(ctx context.Context, tokenStr string) (string, error) {
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}

	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("token is missing a kid header")
			}
			return v.keys.Key(ctx, kid)
		}, opts...)
	if err != nil || !token.Valid {
		return "", ErrInvalidToken
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.Subject == "" {
		return "", ErrInvalidToken
	}
	return claims.Subject, nil
}
