package oidcclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/pkce"
	"github.com/int128/oauth2cli"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_oidcclient/mock_oidcclient.go github.com/int128/kubelogin/pkg/adaptors/oidcclient FactoryInterface,Interface

// Set provides an implementation and interface for OIDC.
var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
)

type Interface interface {
	AuthenticateByCode(ctx context.Context, bindAddress []string, localServerReadyChan chan<- string) (*TokenSet, error)
	AuthenticateByPassword(ctx context.Context, username, password string) (*TokenSet, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenSet, error)
}

// TokenSet represents an output DTO of
// Interface.AuthenticateByCode, Interface.AuthenticateByPassword and Interface.Refresh.
type TokenSet struct {
	IDToken        string
	RefreshToken   string
	IDTokenSubject string
	IDTokenExpiry  time.Time
	IDTokenClaims  map[string]string // string representation of claims for logging
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
func (c *client) AuthenticateByCode(ctx context.Context, bindAddress []string, localServerReadyChan chan<- string) (*TokenSet, error) {
	ctx = c.wrapContext(ctx)
	nonce, err := newNonce()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a nonce parameter")
	}
	p, err := pkce.New()
	if err != nil {
		return nil, xerrors.Errorf("could not generate PKCE parameters: %w", err)
	}
	config := oauth2cli.Config{
		OAuth2Config: c.oauth2Config,
		AuthCodeOptions: []oauth2.AuthCodeOption{
			oauth2.AccessTypeOffline,
			oidc.Nonce(nonce),
			pkce.CodeChallenge(p.CodeChallenge),
			pkce.CodeChallengeMethod(p.CodeChallengeMethod),
		},
		TokenRequestOptions: []oauth2.AuthCodeOption{
			pkce.CodeVerifier(p.CodeVerifier),
		},
		LocalServerBindAddress: bindAddress,
		LocalServerReadyChan:   localServerReadyChan,
	}
	token, err := oauth2cli.GetToken(ctx, config)
	if err != nil {
		return nil, xerrors.Errorf("could not get a token: %w", err)
	}
	return c.parseToken(ctx, token)
}

func newNonce() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", xerrors.Errorf("error while reading random: %w", err)
	}
	return fmt.Sprintf("%x", n), nil
}

// AuthenticateByPassword performs the resource owner password credentials flow.
func (c *client) AuthenticateByPassword(ctx context.Context, username, password string) (*TokenSet, error) {
	ctx = c.wrapContext(ctx)
	token, err := c.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, xerrors.Errorf("could not get a token: %w", err)
	}
	return c.parseToken(ctx, token)
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
	return c.parseToken(ctx, token)
}

func (c *client) parseToken(ctx context.Context, token *oauth2.Token) (*TokenSet, error) {
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
	return &TokenSet{
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

func dumpRawClaims(rawClaims map[string]interface{}) map[string]string {
	claims := make(map[string]string)
	for k, v := range rawClaims {
		switch v := v.(type) {
		case float64:
			claims[k] = fmt.Sprintf("%.f", v)
		default:
			claims[k] = fmt.Sprintf("%v", v)
		}
	}
	return claims
}
