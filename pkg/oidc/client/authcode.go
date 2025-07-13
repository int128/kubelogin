package client

import (
	"context"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/pkce"
	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
)

type AuthCodeURLInput struct {
	State                  string
	Nonce                  string
	PKCEParams             pkce.Params
	AuthRequestExtraParams map[string]string
}

type ExchangeAuthCodeInput struct {
	Code       string
	PKCEParams pkce.Params
	Nonce      string
}

type GetTokenByAuthCodeInput struct {
	AuthCodeURLInput
	BindAddress            []string
	RedirectURLHostname    string // DEPRECATED
	LocalServerSuccessHTML string
	LocalServerCertFile    string
	LocalServerKeyFile     string
}

func (c *client) NegotiatedPKCEMethod() pkce.Method {
	return c.negotiatedPKCEMethod
}

// GetTokenByAuthCode performs the authorization code flow.
func (c *client) GetTokenByAuthCode(ctx context.Context, in GetTokenByAuthCodeInput, localServerReadyChan chan<- string) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	config := oauth2cli.Config{
		OAuth2Config:           c.oauth2Config,
		State:                  in.State,
		AuthCodeOptions:        authorizationRequestOptions(in.AuthCodeURLInput),
		TokenRequestOptions:    tokenRequestOptions(in.PKCEParams),
		LocalServerBindAddress: in.BindAddress,
		LocalServerReadyChan:   localServerReadyChan,
		RedirectURLHostname:    in.RedirectURLHostname,
		LocalServerSuccessHTML: in.LocalServerSuccessHTML,
		LocalServerCertFile:    in.LocalServerCertFile,
		LocalServerKeyFile:     in.LocalServerKeyFile,
		Logf:                   c.logger.V(1).Infof,
	}
	token, err := oauth2cli.GetToken(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("oauth2 error: %w", err)
	}
	return c.verifyToken(ctx, token, in.Nonce)
}

// GetAuthCodeURL returns the URL of authentication request for the authorization code flow.
func (c *client) GetAuthCodeURL(in AuthCodeURLInput) string {
	return c.oauth2Config.AuthCodeURL(in.State, authorizationRequestOptions(in)...)
}

// ExchangeAuthCode exchanges the authorization code and token.
func (c *client) ExchangeAuthCode(ctx context.Context, in ExchangeAuthCodeInput) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	opts := tokenRequestOptions(in.PKCEParams)
	token, err := c.oauth2Config.Exchange(ctx, in.Code, opts...)
	if err != nil {
		return nil, fmt.Errorf("exchange error: %w", err)
	}
	return c.verifyToken(ctx, token, in.Nonce)
}

func authorizationRequestOptions(in AuthCodeURLInput) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		gooidc.Nonce(in.Nonce),
	}
	if pkceOpt := in.PKCEParams.AuthCodeOption(); pkceOpt != nil {
		opts = append(opts, pkceOpt)
	}
	for key, value := range in.AuthRequestExtraParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}
	return opts
}

func tokenRequestOptions(pkceParams pkce.Params) []oauth2.AuthCodeOption {
	if pkceOpt := pkceParams.TokenRequestOption(); pkceOpt != nil {
		return []oauth2.AuthCodeOption{pkceOpt}
	}
	return nil
}
