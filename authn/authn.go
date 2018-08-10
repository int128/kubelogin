package authn

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/authz"
	"golang.org/x/oauth2"
)

// TokenSet is a set of tokens and claims.
type TokenSet struct {
	IDToken      string
	RefreshToken string
	Claims       *Claims
}

// Claims represents properties in the ID token.
type Claims struct {
	Email string `json:"email"`
}

// GetTokenSet retrieves a token from the OIDC provider.
func GetTokenSet(ctx context.Context, issuer string, clientID string, clientSecret string) (*TokenSet, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("Could not access OIDC issuer: %s", err)
	}
	flow := authz.BrowserAuthCodeFlow{
		Port: 8000,
		Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		},
	}
	token, err := flow.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("Could not get a token: %s", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("Could not verify the id_token: %s", err)
	}
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("Could not extract claims from the token response: %s", err)
	}
	return &TokenSet{
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		Claims:       &claims,
	}, nil
}
