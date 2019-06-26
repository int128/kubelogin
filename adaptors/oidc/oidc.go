package oidc

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/oidc/logging"
	"github.com/int128/kubelogin/adaptors/oidc/tls"
	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

// Set provides an implementation and interface for OIDC.
var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(adaptors.OIDC), new(*Factory)),
)

type Factory struct {
	Logger adaptors.Logger
}

func (f *Factory) New(ctx context.Context, config adaptors.OIDCClientConfig) (adaptors.OIDCClient, error) {
	tlsConfig, err := tls.NewConfig(config, f.Logger)
	if err != nil {
		return nil, xerrors.Errorf("could not initialize TLS config: %w", err)
	}
	baseTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	loggingTransport := &logging.Transport{
		Base:   baseTransport,
		Logger: f.Logger,
	}
	httpClient := &http.Client{
		Transport: loggingTransport,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	provider, err := oidc.NewProvider(ctx, config.Config.IDPIssuerURL)
	if err != nil {
		return nil, xerrors.Errorf("could not discovery the OIDC issuer: %w", err)
	}
	return &client{
		httpClient: httpClient,
		provider:   provider,
		oauth2Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     config.Config.ClientID,
			ClientSecret: config.Config.ClientSecret,
			Scopes:       append(config.Config.ExtraScopes, oidc.ScopeOpenID),
		},
	}, nil
}

type client struct {
	httpClient   *http.Client
	provider     *oidc.Provider
	oauth2Config oauth2.Config
}

func (c *client) AuthenticateByCode(ctx context.Context, in adaptors.OIDCAuthenticateByCodeIn) (*adaptors.OIDCAuthenticateOut, error) {
	if c.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	config := oauth2cli.Config{
		OAuth2Config:       c.oauth2Config,
		LocalServerPort:    in.LocalServerPort,
		SkipOpenBrowser:    in.SkipOpenBrowser,
		AuthCodeOptions:    []oauth2.AuthCodeOption{oauth2.AccessTypeOffline},
		ShowLocalServerURL: in.ShowLocalServerURL.ShowLocalServerURL,
	}
	token, err := oauth2cli.GetToken(ctx, config)
	if err != nil {
		return nil, xerrors.Errorf("could not get a token: %w", err)
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, xerrors.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := c.provider.Verifier(&oidc.Config{ClientID: c.oauth2Config.ClientID})
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, xerrors.Errorf("could not verify the id_token: %w", err)
	}
	return &adaptors.OIDCAuthenticateOut{
		VerifiedIDToken: verifiedIDToken,
		IDToken:         idToken,
		RefreshToken:    token.RefreshToken,
	}, nil
}

func (c *client) AuthenticateByPassword(ctx context.Context, in adaptors.OIDCAuthenticateByPasswordIn) (*adaptors.OIDCAuthenticateOut, error) {
	if c.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	token, err := c.oauth2Config.PasswordCredentialsToken(ctx, in.Username, in.Password)
	if err != nil {
		return nil, xerrors.Errorf("could not get a token: %w", err)
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, xerrors.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := c.provider.Verifier(&oidc.Config{ClientID: c.oauth2Config.ClientID})
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, xerrors.Errorf("could not verify the id_token: %w", err)
	}
	return &adaptors.OIDCAuthenticateOut{
		VerifiedIDToken: verifiedIDToken,
		IDToken:         idToken,
		RefreshToken:    token.RefreshToken,
	}, nil
}

func (c *client) Verify(ctx context.Context, in adaptors.OIDCVerifyIn) (*oidc.IDToken, error) {
	if c.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	verifier := c.provider.Verifier(&oidc.Config{ClientID: c.oauth2Config.ClientID})
	verifiedIDToken, err := verifier.Verify(ctx, in.IDToken)
	if err != nil {
		return nil, xerrors.Errorf("could not verify the id_token: %w", err)
	}
	return verifiedIDToken, nil
}
