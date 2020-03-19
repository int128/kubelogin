package oidcclient

import (
	"context"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/domain/jwt"
	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_oidcclient/mock_oidcclient.go github.com/int128/kubelogin/pkg/adaptors/oidcclient Interface

var Set = wire.NewSet(
	wire.Value(NewFunc(New)),
)

type Interface interface {
	GetAuthCodeURL(in AuthCodeURLInput) string
	ExchangeAuthCode(ctx context.Context, in ExchangeAuthCodeInput) (*TokenSet, error)
	GetTokenByAuthCode(ctx context.Context, in GetTokenByAuthCodeInput, localServerReadyChan chan<- string) (*TokenSet, error)
	GetTokenByROPC(ctx context.Context, username, password string) (*TokenSet, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenSet, error)
}

type AuthCodeURLInput struct {
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
}

type ExchangeAuthCodeInput struct {
	Code         string
	CodeVerifier string
	Nonce        string
	RedirectURI  string
}

type GetTokenByAuthCodeInput struct {
	BindAddress         []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	CodeVerifier        string
}

// TokenSet represents an output DTO of
// Interface.GetTokenByAuthCode, Interface.GetTokenByROPC and Interface.Refresh.
type TokenSet struct {
	IDToken       string
	RefreshToken  string
	IDTokenClaims jwt.Claims
}

type client struct {
	httpClient     *http.Client
	provider       *oidc.Provider
	oauth2Config   oauth2.Config
	logger         logger.Interface
	extraURLParams map[string]string
}

func (c *client) wrapContext(ctx context.Context) context.Context {
	if c.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	return ctx
}

// GetTokenByAuthCode performs the authorization code flow.
func (c *client) GetTokenByAuthCode(ctx context.Context, in GetTokenByAuthCodeInput, localServerReadyChan chan<- string) (*TokenSet, error) {
	ctx = c.wrapContext(ctx)
	config := oauth2cli.Config{
		OAuth2Config: c.oauth2Config,
		State:        in.State,
		AuthCodeOptions: []oauth2.AuthCodeOption{
			oauth2.AccessTypeOffline,
			oidc.Nonce(in.Nonce),
			oauth2.SetAuthURLParam("code_challenge", in.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", in.CodeChallengeMethod),
		},
		TokenRequestOptions: []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("code_verifier", in.CodeVerifier),
		},
		LocalServerBindAddress: in.BindAddress,
		LocalServerReadyChan:   localServerReadyChan,
	}

	for key, value := range c.extraURLParams {
		config.AuthCodeOptions = append(config.AuthCodeOptions, oauth2.SetAuthURLParam(key, value))
	}

	token, err := oauth2cli.GetToken(ctx, config)
	if err != nil {
		return nil, xerrors.Errorf("oauth2 error: %w", err)
	}
	return c.verifyToken(ctx, token, in.Nonce)
}

// GetAuthCodeURL returns the URL of authentication request for the authorization code flow.
func (c *client) GetAuthCodeURL(in AuthCodeURLInput) string {
	cfg := c.oauth2Config
	cfg.RedirectURL = in.RedirectURI
	return cfg.AuthCodeURL(in.State,
		oauth2.AccessTypeOffline,
		oidc.Nonce(in.Nonce),
		oauth2.SetAuthURLParam("code_challenge", in.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", in.CodeChallengeMethod),
	)
}

// ExchangeAuthCode exchanges the authorization code and token.
func (c *client) ExchangeAuthCode(ctx context.Context, in ExchangeAuthCodeInput) (*TokenSet, error) {
	ctx = c.wrapContext(ctx)
	cfg := c.oauth2Config
	cfg.RedirectURL = in.RedirectURI
	token, err := cfg.Exchange(ctx, in.Code, oauth2.SetAuthURLParam("code_verifier", in.CodeVerifier))
	if err != nil {
		return nil, xerrors.Errorf("exchange error: %w", err)
	}
	return c.verifyToken(ctx, token, in.Nonce)
}

// GetTokenByROPC performs the resource owner password credentials flow.
func (c *client) GetTokenByROPC(ctx context.Context, username, password string) (*TokenSet, error) {
	ctx = c.wrapContext(ctx)
	token, err := c.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, xerrors.Errorf("resource owner password credentials flow error: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}

// Refresh sends a refresh token request and returns a token set.
func (c *client) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	ctx = c.wrapContext(ctx)
	currentToken := &oauth2.Token{
		Expiry:       time.Now(),
		RefreshToken: refreshToken,
	}
	source := c.oauth2Config.TokenSource(ctx, currentToken)
	token, err := source.Token()
	if err != nil {
		return nil, xerrors.Errorf("could not refresh the token: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}

// verifyToken verifies the token with the certificates of the provider and the nonce.
// If the nonce is an empty string, it does not verify the nonce.
func (c *client) verifyToken(ctx context.Context, token *oauth2.Token, nonce string) (*TokenSet, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, xerrors.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := c.provider.Verifier(&oidc.Config{ClientID: c.oauth2Config.ClientID})
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, xerrors.Errorf("could not verify the ID token: %w", err)
	}
	if nonce != "" && nonce != verifiedIDToken.Nonce {
		return nil, xerrors.Errorf("nonce did not match (wants %s but got %s)", nonce, verifiedIDToken.Nonce)
	}
	pretty, err := jwt.DecodePayloadAsPrettyJSON(idToken)
	if err != nil {
		return nil, xerrors.Errorf("could not decode the token: %w", err)
	}
	return &TokenSet{
		IDToken: idToken,
		IDTokenClaims: jwt.Claims{
			Subject: verifiedIDToken.Subject,
			Expiry:  verifiedIDToken.Expiry,
			Pretty:  pretty,
		},
		RefreshToken: token.RefreshToken,
	}, nil
}
