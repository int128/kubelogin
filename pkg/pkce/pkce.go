// Package pkce provides generation of the PKCE parameters.
// See also https://tools.ietf.org/html/rfc7636.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

type Method int

const (
	// Code challenge methods defined as https://tools.ietf.org/html/rfc7636#section-4.3
	NoMethod Method = iota
	MethodS256
)

// Params represents a set of the PKCE parameters.
type Params struct {
	CodeChallenge       string
	CodeChallengeMethod string
	CodeVerifier        string
}

// New returns a parameters supported by the provider.
// You need to pass the code challenge methods defined in RFC7636.
// It returns a zero value if no method is available.
func New(method Method) (Params, error) {
	if method == MethodS256 {
		return NewS256()
	}
	return Params{}, nil
}

// NewS256 generates a parameters for S256.
func NewS256() (Params, error) {
	b, err := random32()
	if err != nil {
		return Params{}, fmt.Errorf("could not generate a random: %w", err)
	}
	return computeS256(b), nil
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	return b, nil
}

func computeS256(b []byte) Params {
	v := base64URLEncode(b)
	s := sha256.New()
	_, _ = s.Write([]byte(v))
	return Params{
		CodeChallenge:       base64URLEncode(s.Sum(nil)),
		CodeChallengeMethod: "S256",
		CodeVerifier:        v,
	}
}

func base64URLEncode(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
