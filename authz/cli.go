package authz

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/oauth2"
)

// CLIAuthCodeFlow is a flow to get a token by keyboard interaction.
type CLIAuthCodeFlow struct {
	oauth2.Config
}

// GetToken returns a token by browser interaction.
func (f *CLIAuthCodeFlow) GetToken(ctx context.Context) (*oauth2.Token, error) {
	f.Config.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
	state, err := generateOAuthState()
	if err != nil {
		return nil, err
	}
	authCodeURL := f.Config.AuthCodeURL(state)
	log.Printf("Open %s for authorization", authCodeURL)
	fmt.Print("Enter code: ")
	var code string
	if _, err := fmt.Scanln(&code); err != nil {
		return nil, err
	}
	token, err := f.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("Could not exchange oauth code: %s", err)
	}
	return token, nil
}
