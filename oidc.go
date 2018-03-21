package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDCToken is a token set
type OIDCToken struct {
	IDToken      string
	RefreshToken string
	IDTokenClaim *IDTokenClaim
}

// IDTokenClaim represents an ID token decoded
type IDTokenClaim struct {
	Email string `json:"email"`
}

// GetOIDCTokenByAuthCode returns a token retrieved by auth code grant
func GetOIDCTokenByAuthCode(issuer string, clientID string, clientSecret string) (*OIDCToken, error) {
	provider, err := oidc.NewProvider(oauth2.NoContext, issuer)
	if err != nil {
		return nil, err
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	state, err := generateState()
	if err != nil {
		return nil, err
	}

	authCodeURL := config.AuthCodeURL(state)
	fmt.Printf(`---- Authentication ----
1. Open the following URL:

%s

2. Enter the code: `, authCodeURL)
	var code string
	if _, err := fmt.Scanln(&code); err != nil {
		return nil, err
	}
	fmt.Println()

	token, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("id_token is missing in the token response: %s", token)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	idToken, err := verifier.Verify(oauth2.NoContext, rawIDToken)
	if err != nil {
		return nil, err
	}

	idTokenClaim := IDTokenClaim{}
	if err := idToken.Claims(&idTokenClaim); err != nil {
		return nil, err
	}

	return &OIDCToken{
		IDToken:      rawIDToken,
		IDTokenClaim: &idTokenClaim,
		RefreshToken: token.RefreshToken,
	}, nil
}

func generateState() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", n), nil
}
