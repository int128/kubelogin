package oidc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

type Interface interface {
	AuthenticateByCode(ctx context.Context, in AuthenticateByCodeIn) (*AuthenticateOut, error)
	AuthenticateByPassword(ctx context.Context, in AuthenticateByPasswordIn) (*AuthenticateOut, error)
	Refresh(ctx context.Context, in RefreshIn) (*AuthenticateOut, error)
}

// AuthenticateByCodeIn represents an input DTO of Interface.AuthenticateByCode.
type AuthenticateByCodeIn struct {
	LocalServerPort    []int // HTTP server port candidates
	SkipOpenBrowser    bool  // skip opening browser if true
	ShowLocalServerURL interface{ ShowLocalServerURL(url string) }
}

// AuthenticateByPasswordIn represents an input DTO of Interface.AuthenticateByPassword.
type AuthenticateByPasswordIn struct {
	Username string
	Password string
}

// AuthenticateOut represents an output DTO of
// Interface.AuthenticateByCode, Interface.AuthenticateByPassword and Interface.Refresh.
type AuthenticateOut struct {
	IDToken       string
	RefreshToken  string
	IDTokenExpiry time.Time
	IDTokenClaims map[string]string // string representation of claims for logging
}

// RefreshIn represents an input DTO of Interface.Refresh.
type RefreshIn struct {
	RefreshToken string
}

type client struct {
	httpClient   *http.Client
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	logger       logger.Interface
}

func (c *client) wrapContext(ctx context.Context) context.Context {
	if c.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	return ctx
}

// AuthenticateByCode performs the authorization code flow.
func (c *client) AuthenticateByCode(ctx context.Context, in AuthenticateByCodeIn) (*AuthenticateOut, error) {
	ctx = c.wrapContext(ctx)
	nonce, err := newNonce()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a nonce parameter")
	}
	config := oauth2cli.Config{
		OAuth2Config:       c.oauth2Config,
		LocalServerPort:    in.LocalServerPort,
		SkipOpenBrowser:    in.SkipOpenBrowser,
		AuthCodeOptions:    []oauth2.AuthCodeOption{oauth2.AccessTypeOffline, oidc.Nonce(nonce)},
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
	if verifiedIDToken.Nonce != nonce {
		return nil, xerrors.Errorf("nonce of ID token did not match (want %s but was %s)", nonce, verifiedIDToken.Nonce)
	}
	claims, err := dumpClaims(verifiedIDToken)
	if err != nil {
		c.logger.V(1).Infof("incomplete claims of the ID token: %w", err)
	}
	return &AuthenticateOut{
		IDToken:       idToken,
		RefreshToken:  token.RefreshToken,
		IDTokenExpiry: verifiedIDToken.Expiry,
		IDTokenClaims: claims,
	}, nil
}

func newNonce() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", xerrors.Errorf("error while reading random: %w", err)
	}
	return fmt.Sprintf("%x", n), nil
}

// AuthenticateByPassword performs the resource owner password credentials flow.
func (c *client) AuthenticateByPassword(ctx context.Context, in AuthenticateByPasswordIn) (*AuthenticateOut, error) {
	ctx = c.wrapContext(ctx)
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
		c.logger.V(1).Infof("incomplete claims of the ID token: %w", err)
	}
	return &AuthenticateOut{
		IDToken:       idToken,
		RefreshToken:  token.RefreshToken,
		IDTokenExpiry: verifiedIDToken.Expiry,
		IDTokenClaims: claims,
	}, nil
}

// Refresh sends a refresh token request and returns a token set.
func (c *client) Refresh(ctx context.Context, in RefreshIn) (*AuthenticateOut, error) {
	ctx = c.wrapContext(ctx)
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
		c.logger.V(1).Infof("incomplete claims of the ID token: %w", err)
	}
	return &AuthenticateOut{
		IDToken:       idToken,
		RefreshToken:  token.RefreshToken,
		IDTokenExpiry: verifiedIDToken.Expiry,
		IDTokenClaims: claims,
	}, nil
}

func dumpClaims(token *oidc.IDToken) (map[string]string, error) {
	var rawClaims map[string]interface{}
	err := token.Claims(&rawClaims)
	return dumpRawClaims(rawClaims), err
}
