package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDCToken is a token set
type OIDCToken struct {
	IDToken      string
	RefreshToken string
}

// GetOIDCToken returns a token retrieved by auth code grant
func GetOIDCToken(issuer string, clientID string, clientSecret string) (*OIDCToken, error) {
	port := 8000
	provider, err := oidc.NewProvider(oauth2.NoContext, issuer)
	if err != nil {
		return nil, err
	}

	state, err := generateState()
	if err != nil {
		return nil, err
	}

	webBrowserConfig := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("http://localhost:%d/", port),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "groups", "offline_access", "profile"},
	}

	cliConfig := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "groups", "offline_access", "profile"},
	}

	showInstructionToGetToken(webBrowserConfig.RedirectURL, cliConfig.AuthCodeURL(state))
	token, err := getTokenByWebBrowserOrCLI(webBrowserConfig, cliConfig, state)

	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("id_token is missing in the token response: %s", token)
	}

	log.Printf("Verifying ID token...")
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(oauth2.NoContext, rawIDToken)
	if err != nil {
		return nil, err
	}

	idTokenClaim := struct {
		Email string `json:"email"`
	}{}
	if err := idToken.Claims(&idTokenClaim); err != nil {
		return nil, err
	}

	log.Printf("You are logged in as %s (%s)", idTokenClaim.Email, idToken.Subject)
	return &OIDCToken{
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

func getTokenByWebBrowserOrCLI(webBrowserConfig oauth2.Config, cliConfig oauth2.Config, state string) (*oauth2.Token, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	webBrowserAuthCodeCh := make(chan string)
	cliAuthCodeCh := make(chan string)
	errCh := make(chan error)

	go ReceiveAuthCodeFromWebBrowser(ctx, webBrowserConfig.AuthCodeURL(state), state, webBrowserAuthCodeCh, errCh)
	go ReceiveAuthCodeFromCLI(ctx, cliAuthCodeCh, errCh)

	select {
	case err := <-errCh:
		return nil, err

	case authCode := <-webBrowserAuthCodeCh:
		log.Printf("Exchanging code and token...")
		return webBrowserConfig.Exchange(ctx, authCode)

	case authCode := <-cliAuthCodeCh:
		log.Printf("Exchanging code and token...")
		return cliConfig.Exchange(ctx, authCode)
	}
}

func showInstructionToGetToken(localhostURL string, cliAuthCodeURL string) {
	log.Printf("Starting OpenID Connect authentication:")
	fmt.Printf(`
## Automatic (recommended)

Open the following URL in the web browser:

%s

## Manual

If you cannot access to localhost, instead open the following URL:

%s

Enter the code: `, localhostURL, cliAuthCodeURL)
}

func generateState() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", n), nil
}
