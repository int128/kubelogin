package jwtdecoder

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestDecoder_Decode(t *testing.T) {
	var decoder Decoder

	t.Run("ValidToken", func(t *testing.T) {
		expiry := time.Now().Round(time.Second)
		idToken := newIDToken(t, "https://issuer.example.com", expiry)
		decodedToken, err := decoder.Decode(idToken)
		if err != nil {
			t.Fatalf("Decode error: %s", err)
		}
		if decodedToken.Expiry != expiry {
			t.Errorf("Expiry wants %s but %s", expiry, decodedToken.Expiry)
		}
		t.Logf("Pretty=%+v", decodedToken.Pretty)
	})
	t.Run("InvalidToken", func(t *testing.T) {
		decodedToken, err := decoder.Decode("HEADER.INVALID_TOKEN.SIGNATURE")
		if err == nil {
			t.Errorf("error wants non-nil but nil")
		} else {
			t.Logf("expected error: %+v", err)
		}
		if decodedToken != nil {
			t.Errorf("decodedToken wants nil but %+v", decodedToken)
		}
	})
}

func newIDToken(t *testing.T, issuer string, expiry time.Time) string {
	t.Helper()
	claims := struct {
		jwt.StandardClaims
		Nonce         string   `json:"nonce"`
		Groups        []string `json:"groups"`
		EmailVerified bool     `json:"email_verified"`
	}{
		StandardClaims: jwt.StandardClaims{
			Issuer:    issuer,
			Audience:  "kubernetes",
			Subject:   "SUBJECT",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: expiry.Unix(),
		},
		Nonce:         "NONCE",
		Groups:        []string{"admin", "users"},
		EmailVerified: false,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(readPrivateKey(t, "testdata/jws.key"))
	if err != nil {
		t.Fatalf("Could not sign the claims: %s", err)
	}
	return s
}

func readPrivateKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	b, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatalf("could not read the file: %s", err)
	}
	block, rest := pem.Decode(b)
	if block == nil {
		t.Fatalf("could not decode PEM")
	}
	if len(rest) > 0 {
		t.Fatalf("PEM should contain single key but multiple keys")
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("could not parse the key: %s", err)
	}
	return k
}
