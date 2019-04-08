package adaptors

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/oauth2cli"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type OIDC struct{}

func (*OIDC) Authenticate(ctx context.Context, in adaptors.OIDCAuthenticateIn) (*adaptors.OIDCAuthenticateOut, error) {
	if in.Client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, in.Client)
	}
	provider, err := oidc.NewProvider(ctx, in.Issuer)
	if err != nil {
		return nil, errors.Wrapf(err, "could not discovery the OIDC issuer")
	}
	flow := oauth2cli.AuthCodeFlow{
		Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     in.ClientID,
			ClientSecret: in.ClientSecret,
			Scopes:       append(in.ExtraScopes, oidc.ScopeOpenID),
		},
		LocalServerPort: in.LocalServerPort,
		SkipOpenBrowser: in.SkipOpenBrowser,
		AuthCodeOptions: []oauth2.AuthCodeOption{oauth2.AccessTypeOffline},
	}
	token, err := flow.GetToken(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get a token")
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.Errorf("id_token is missing in the token response: %s", token)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: in.ClientID})
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
