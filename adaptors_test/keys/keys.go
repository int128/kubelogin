package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func New(t *testing.T) Keys {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Could not generate a key pair: %s", err)
	}
	return Keys{
		IDTokenKeyPair: k,
	}
}

type Keys struct {
	IDTokenKeyPair *rsa.PrivateKey // a key pair for signing ID tokens
}

func (c *Keys) SignClaims(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(c.IDTokenKeyPair)
	if err != nil {
		t.Fatalf("Could not sign the claims: %s", err)
	}
	return s
}
