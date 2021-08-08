package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

var PrivateKey = generateKey(1024)

func generateKey(b int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return k
}

type Claims struct {
	jwt.StandardClaims
	// aud claim is either a string or an array of strings.
	// https://tools.ietf.org/html/rfc7519#section-4.1.3
	Audience      []string `json:"aud,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
}

func Encode(t *testing.T, claims Claims) string {
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(PrivateKey)
	if err != nil {
		t.Fatalf("could not encode JWT: %s", err)
	}
	return s
}

func EncodeF(t *testing.T, mutation func(*Claims)) string {
	var claims Claims
	mutation(&claims)
	return Encode(t, claims)
}
