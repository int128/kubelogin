package oidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

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

// New returns an instance of adaptors.OIDCClient with the given configuration.
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
		logger: f.Logger,
	}, nil
}

type client struct {
	httpClient   *http.Client
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	logger       adaptors.Logger
}

// AuthenticateByCode performs the authorization code flow.
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
	claims, err := dumpClaims(verifiedIDToken)
	if err != nil {
		c.logger.Debugf(1, "incomplete claims of the ID token: %w", err)
	}
	return &adaptors.OIDCAuthenticateOut{
		IDToken:       idToken,
		RefreshToken:  token.RefreshToken,
		IDTokenExpiry: verifiedIDToken.Expiry,
		IDTokenClaims: claims,
	}, nil
}

// AuthenticateByPassword performs the resource owner password credentials flow.
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
	claims, err := dumpClaims(verifiedIDToken)
	if err != nil {
		c.logger.Debugf(1, "incomplete claims of the ID token: %w", err)
	}
	return &adaptors.OIDCAuthenticateOut{
		IDToken:       idToken,
		RefreshToken:  token.RefreshToken,
		IDTokenExpiry: verifiedIDToken.Expiry,
		IDTokenClaims: claims,
	}, nil
}

// Verify checks client ID and signature of the ID token.
// This does not check the expiration and caller should check it.
func (c *client) Verify(ctx context.Context, in adaptors.OIDCVerifyIn) (*adaptors.OIDCVerifyOut, error) {
	if c.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	verifier := c.provider.Verifier(&oidc.Config{
		ClientID:        c.oauth2Config.ClientID,
		SkipExpiryCheck: true,
	})
	verifiedIDToken, err := verifier.Verify(ctx, in.IDToken)
	if err != nil {
		return nil, xerrors.Errorf("could not verify the id_token: %w", err)
	}
	claims, err := dumpClaims(verifiedIDToken)
	if err != nil {
		c.logger.Debugf(1, "incomplete claims of the ID token: %w", err)
	}
	return &adaptors.OIDCVerifyOut{
		IDTokenExpiry: verifiedIDToken.Expiry,
		IDTokenClaims: claims,
	}, nil
}

// Refresh sends a refresh token request and returns a token set.
func (c *client) Refresh(ctx context.Context, in adaptors.OIDCRefreshIn) (*adaptors.OIDCAuthenticateOut, error) {
	currentToken := &oauth2.Token{
		Expiry:       time.Now(),
		RefreshToken: in.RefreshToken,
	}
	source := c.oauth2Config.TokenSource(ctx, currentToken)
	token, err := source.Token()
	if err != nil {
		return nil, xerrors.Errorf("could not refresh the token: %w", err)
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
	claims, err := dumpClaims(verifiedIDToken)
	if err != nil {
		c.logger.Debugf(1, "incomplete claims of the ID token: %w", err)
	}
	return &adaptors.OIDCAuthenticateOut{
		IDToken:       idToken,
		RefreshToken:  token.RefreshToken,
		IDTokenExpiry: verifiedIDToken.Expiry,
		IDTokenClaims: claims,
	}, nil
}

func dumpClaims(token *oidc.IDToken) (map[string]string, error) {
	var rawClaims map[string]interface{}
	err := token.Claims(&rawClaims)
	claims := make(map[string]string)
	for k, v := range rawClaims {
		switch v.(type) {
		case float64:
			claims[k] = fmt.Sprintf("%f", v.(float64))
		default:
			claims[k] = fmt.Sprintf("%s", v)
		}
	}
	if err != nil {
		return claims, xerrors.Errorf("error while decoding the ID token: %w", err)
	}
	return claims, nil
}
