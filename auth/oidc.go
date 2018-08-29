package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// TokenSet is a set of tokens and claims.
type TokenSet struct {
	IDToken      string
	RefreshToken string
}

// Config represents OIDC configuration.
type Config struct {
	Issuer          string
	ClientID        string
	ClientSecret    string
	ExtraScopes     []string     // Additional scopes
	Client          *http.Client // HTTP client for oidc and oauth2
	ServerPort      int          // HTTP server port
	SkipOpenBrowser bool         // skip opening browser if true
}

// GetTokenSet retrives a token from the OIDC provider and returns a TokenSet.
func (c *Config) GetTokenSet(ctx context.Context) (*TokenSet, error) {
	if c.Client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.Client)
	}
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("Could not discovery the OIDC issuer: %s", err)
	}
	oauth2Config := &oauth2.Config{
		Endpoint:     provider.Endpoint(),
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       append(c.ExtraScopes, oidc.ScopeOpenID, oidc.ScopeOfflineAccess),
		RedirectURL:  fmt.Sprintf("http://localhost:%d/", c.ServerPort),
	}
	flow := &authCodeFlow{
		ServerPort:      c.ServerPort,
		SkipOpenBrowser: c.SkipOpenBrowser,
		Config:          oauth2Config,
	}
	token, err := flow.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("Could not get a token: %s", err)
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: c.ClientID})
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("Could not verify the id_token: %s", err)
	}
	log.Printf("Got token for subject=%s", verifiedIDToken.Subject)
	return &TokenSet{
		IDToken:      idToken,
		RefreshToken: token.RefreshToken,
	}, nil
}
