package adaptors

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/oauth2cli"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type OIDC struct{}

func (*OIDC) Authenticate(ctx context.Context, in adaptors.OIDCAuthenticateIn) (*adaptors.OIDCAuthenticateOut, error) {
	if in.Client != nil {
		// https://github.com/int128/kubelogin/issues/31
		val, ok := os.LookupEnv("HTTPS_PROXY")
		if ok {
			proxyURL, err := url.Parse(val)
			if err != nil {
				log.Printf("HTTPS_PROXY %s cannot be parsed into a URL\n", val)
			} else {
				transport := &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				}
				in.Client = &http.Client{
					Transport: transport,
				}
			}
		}
		//
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
	log.Printf("Got token for subject=%s", verifiedIDToken.Subject)
	return &adaptors.OIDCAuthenticateOut{
		IDToken:      idToken,
		RefreshToken: token.RefreshToken,
	}, nil
}
