package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/int128/kubelogin/pkg/jwt"
)

// Provider represents an OIDC provider.
type Provider struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string   // optional
	ExtraScopes  []string // optional
	UsePKCE      bool     // optional
}

// TokenSet represents a set of ID token and refresh token.
type TokenSet struct {
	IDToken      string
	RefreshToken string
}

func (ts TokenSet) DecodeWithoutVerify() (*jwt.Claims, error) {
	return jwt.DecodeWithoutVerify(ts.IDToken)
}

func NewState() (string, error) {
	b, err := random32()
	if err != nil {
		return "", fmt.Errorf("could not generate a random: %w", err)
	}
	return base64URLEncode(b), nil
}

func NewNonce() (string, error) {
	b, err := random32()
	if err != nil {
		return "", fmt.Errorf("could not generate a random: %w", err)
	}
	return base64URLEncode(b), nil
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	return b, nil
}

func base64URLEncode(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
