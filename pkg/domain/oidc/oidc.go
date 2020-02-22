package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"golang.org/x/xerrors"
)

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

type PKCEParams struct {
	CodeChallenge       string
	CodeChallengeMethod string
	CodeVerifier        string
}

func NewPKCEParams() (*PKCEParams, error) {
	b, err := random32()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a random: %w", err)
	}
	s := computeS256(b)
	return &s, nil
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if err := binary.Read(rand.Reader, binary.LittleEndian, b); err != nil {
		return nil, xerrors.Errorf("read error: %w", err)
	}
	return b, nil
}

func computeS256(b []byte) PKCEParams {
	v := base64URLEncode(b)
	s := sha256.New()
	_, _ = s.Write([]byte(v))
	return PKCEParams{
		CodeChallenge:       base64URLEncode(s.Sum(nil)),
		CodeChallengeMethod: "S256",
		CodeVerifier:        v,
	}
}

func base64URLEncode(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
