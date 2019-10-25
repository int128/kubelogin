// Package pkce provides generation of PKCE parameters.
// See https://tools.ietf.org/html/rfc7636
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

// CodeChallenge returns an oauth2.AuthCodeOption of code_challenge.
func CodeChallenge(s string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge", s)
}

// CodeChallengeMethod returns an oauth2.AuthCodeOption of code_challenge_method.
func CodeChallengeMethod(s string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge_method", s)
}

// CodeVerifier returns an oauth2.AuthCodeOption of code_verifier.
func CodeVerifier(s string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_verifier", s)
}

// Params represents a set of parameters.
type Params struct {
	CodeChallenge       string
	CodeChallengeMethod string
	CodeVerifier        string
}

// New generates random bytes and computes a Params.
func New() (*Params, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, xerrors.Errorf("could not generate random bytes: %w", err)
	}
	return computeS256(b), nil
}

func computeS256(b []byte) *Params {
	verifier := base64URLEncode(b)
	s := sha256.New()
	_, _ = s.Write([]byte(verifier))
	challenge := base64URLEncode(s.Sum(nil))
	return &Params{
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		CodeVerifier:        verifier,
	}
}

func base64URLEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
