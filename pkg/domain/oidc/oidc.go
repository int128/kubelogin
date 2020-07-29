package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"

	"github.com/int128/kubelogin/pkg/domain/jwt"
	"golang.org/x/xerrors"
)

// TokenSet represents an output DTO of
// Interface.GetTokenByAuthCode, Interface.GetTokenByROPC and Interface.Refresh.
type TokenSet struct {
	IDToken       string
	RefreshToken  string
	IDTokenClaims jwt.Claims
}

func NewState() (string, error) {
	b, err := random32()
	if err != nil {
		return "", xerrors.Errorf("could not generate a random: %w", err)
	}
	return base64URLEncode(b), nil
}

func NewNonce() (string, error) {
	b, err := random32()
	if err != nil {
		return "", xerrors.Errorf("could not generate a random: %w", err)
	}
	return base64URLEncode(b), nil
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, xerrors.Errorf("read error: %w", err)
	}
	return b, nil
}

func base64URLEncode(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
