// Package authn verifies access tokens issued by ecosystem-auth.
//
// Tokens are HS256 JWTs whose subject is the user ID; the signing secret is
// shared with the auth service, so verification is local and needs no network
// call.
package authn

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid or expired token")

type Verifier struct {
	secret []byte
	issuer string
}

func NewVerifier(secret []byte, issuer string) *Verifier {
	return &Verifier{secret: secret, issuer: issuer}
}

// VerifyAccessToken validates the JWT and returns the user ID (subject).
func (v *Verifier) VerifyAccessToken(tokenStr string) (string, error) {
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"HS256"})}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return v.secret, nil
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
