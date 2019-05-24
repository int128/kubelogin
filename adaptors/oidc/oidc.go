package oidc

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/oauth2cli"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type OIDC struct {
	HTTP adaptors.HTTP
}

func (o *OIDC) NewClient(config adaptors.HTTPClientConfig) (adaptors.OIDCClient, error) {
	hc, err := o.HTTP.NewClient(adaptors.HTTPClientConfig{
		OIDCConfig:                   config.OIDCConfig,
		CertificateAuthorityFilename: config.CertificateAuthorityFilename,
		SkipTLSVerify:                config.SkipTLSVerify,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "could not create a HTTP client")
	}
	return &Client{hc}, nil
}

type Client struct {
	hc *http.Client
}

func (c *Client) AuthenticateByCode(ctx context.Context, in adaptors.OIDCAuthenticateByCodeIn, cb adaptors.OIDCAuthenticateCallback) (*adaptors.OIDCAuthenticateOut, error) {
	if c.hc != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.hc)
	}
	provider, err := oidc.NewProvider(ctx, in.Config.IDPIssuerURL())
	if err != nil {
		return nil, errors.Wrapf(err, "could not discovery the OIDC issuer")
	}
	config := oauth2cli.Config{
		OAuth2Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     in.Config.ClientID(),
			ClientSecret: in.Config.ClientSecret(),
			Scopes:       append(in.Config.ExtraScopes(), oidc.ScopeOpenID),
		},
		LocalServerPort:    in.LocalServerPort,
		SkipOpenBrowser:    in.SkipOpenBrowser,
		AuthCodeOptions:    []oauth2.AuthCodeOption{oauth2.AccessTypeOffline},
		ShowLocalServerURL: cb.ShowLocalServerURL,
	}
	token, err := oauth2cli.GetToken(ctx, config)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get a token")
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: in.Config.ClientID()})
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, errors.Wrapf(err, "could not verify the id_token")
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
	provider, err := oidc.NewProvider(ctx, in.Config.IDPIssuerURL())
	if err != nil {
		return nil, errors.Wrapf(err, "could not discovery the OIDC issuer")
	}
	config := oauth2.Config{
		Endpoint:     provider.Endpoint(),
		ClientID:     in.Config.ClientID(),
		ClientSecret: in.Config.ClientSecret(),
		Scopes:       append(in.Config.ExtraScopes(), oidc.ScopeOpenID),
	}
	token, err := config.PasswordCredentialsToken(ctx, in.Username, in.Password)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get a token")
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: in.Config.ClientID()})
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, errors.Wrapf(err, "could not verify the id_token")
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
	provider, err := oidc.NewProvider(ctx, in.Config.IDPIssuerURL())
	if err != nil {
		return nil, errors.Wrapf(err, "could not discovery the OIDC issuer")
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: in.Config.ClientID()})
	verifiedIDToken, err := verifier.Verify(ctx, in.Config.IDToken())
	if err != nil {
		return nil, errors.Wrapf(err, "could not verify the id_token")
	}
	return verifiedIDToken, nil
}
