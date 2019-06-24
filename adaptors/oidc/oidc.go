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

func (f *Factory) New(config adaptors.OIDCClientConfig) (adaptors.OIDCClient, error) {
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
	hc := &http.Client{
		Transport: loggingTransport,
	}
	return &Client{hc}, nil
}

type Client struct {
	hc *http.Client
}

func (c *Client) AuthenticateByCode(ctx context.Context, in adaptors.OIDCAuthenticateByCodeIn) (*adaptors.OIDCAuthenticateOut, error) {
	if c.hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.hc)
	}
	provider, err := oidc.NewProvider(ctx, in.Config.IDPIssuerURL)
	if err != nil {
		return nil, xerrors.Errorf("could not discovery the OIDC issuer: %w", err)
	}
	config := oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     in.Config.ClientID,
			ClientSecret: in.Config.ClientSecret,
			Scopes:       append(in.Config.ExtraScopes, oidc.ScopeOpenID),
		},
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
	verifier := provider.Verifier(&oidc.Config{ClientID: in.Config.ClientID})
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

func (c *Client) AuthenticateByPassword(ctx context.Context, in adaptors.OIDCAuthenticateByPasswordIn) (*adaptors.OIDCAuthenticateOut, error) {
	if c.hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.hc)
	}
	provider, err := oidc.NewProvider(ctx, in.Config.IDPIssuerURL)
	if err != nil {
		return nil, xerrors.Errorf("could not discovery the OIDC issuer: %w", err)
	}
	config := oauth2.Config{
		Endpoint:     provider.Endpoint(),
		ClientID:     in.Config.ClientID,
		ClientSecret: in.Config.ClientSecret,
		Scopes:       append(in.Config.ExtraScopes, oidc.ScopeOpenID),
	}
	token, err := config.PasswordCredentialsToken(ctx, in.Username, in.Password)
	if err != nil {
		return nil, xerrors.Errorf("could not get a token: %w", err)
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, xerrors.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: in.Config.ClientID})
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

func (c *Client) Verify(ctx context.Context, in adaptors.OIDCVerifyIn) (*oidc.IDToken, error) {
	if c.hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.hc)
	}
	provider, err := oidc.NewProvider(ctx, in.Config.IDPIssuerURL)
	if err != nil {
		return nil, xerrors.Errorf("could not discovery the OIDC issuer: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: in.Config.ClientID})
	verifiedIDToken, err := verifier.Verify(ctx, in.Config.IDToken)
	if err != nil {
		return nil, xerrors.Errorf("could not verify the id_token: %w", err)
	}
	return verifiedIDToken, nil
}
