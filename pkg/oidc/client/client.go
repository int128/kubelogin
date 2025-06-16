package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2dev"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/pkce"
)

type Interface interface {
	GetAuthCodeURL(in AuthCodeURLInput) string
	ExchangeAuthCode(ctx context.Context, in ExchangeAuthCodeInput) (*oidc.TokenSet, error)
	GetTokenByAuthCode(ctx context.Context, in GetTokenByAuthCodeInput, localServerReadyChan chan<- string) (*oidc.TokenSet, error)
	NegotiatedPKCEMethod() pkce.Method
	GetTokenByROPC(ctx context.Context, username, password string) (*oidc.TokenSet, error)
	GetTokenByClientCredentials(ctx context.Context, in GetTokenByClientCredentialsInput) (*oidc.TokenSet, error)
	GetDeviceAuthorization(ctx context.Context) (*oauth2dev.AuthorizationResponse, error)
	ExchangeDeviceCode(ctx context.Context, authResponse *oauth2dev.AuthorizationResponse) (*oidc.TokenSet, error)
	Refresh(ctx context.Context, refreshToken string) (*oidc.TokenSet, error)
}

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
	BindAddress            []string
	State                  string
	Nonce                  string
	PKCEParams             pkce.Params
	RedirectURLHostname    string // DEPRECATED
	AuthRequestExtraParams map[string]string
	LocalServerSuccessHTML string
	LocalServerCertFile    string
	LocalServerKeyFile     string
}

type GetTokenByClientCredentialsInput struct {
	EndpointParams map[string][]string
}

type client struct {
	httpClient                  *http.Client
	provider                    *gooidc.Provider
	oauth2Config                oauth2.Config
	clock                       clock.Interface
	logger                      logger.Interface
	negotiatedPKCEMethod        pkce.Method
	deviceAuthorizationEndpoint string
	useAccessToken              bool
}

func (c *client) wrapContext(ctx context.Context) context.Context {
	if c.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	return ctx
}

// httpTransportFn is a simple type wrapper for a function to make it usable as
// [net/http.Transport].
type httpTransportFn func(req *http.Request) (*http.Response, error)

func (f httpTransportFn) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// GetTokenByAuthCode performs the authorization code flow.
func (c *client) GetTokenByAuthCode(ctx context.Context, in GetTokenByAuthCodeInput, localServerReadyChan chan<- string) (*oidc.TokenSet, error) {
	// Token retrievel fails when an auth code has been retrieved using Azure AD
	// Single Page Application due to the missing "Origin" header for CORS
	// validation.
	//
	// Since oauthcli does not expose a parameter to set headers directly we
	// have to use a workaround by wrapping the http transport to set the header
	// on the request before it is sent.
	//
	// Ref: https://github.com/int128/kubelogin/issues/1048
	origTransport := c.httpClient.Transport
	c.httpClient.Transport = httpTransportFn(func(req *http.Request) (*http.Response, error) {
		req.Header.Set("Origin", in.RedirectURLHostname)
		return origTransport.RoundTrip(req)
	})

	ctx = c.wrapContext(ctx)
	config := oauth2cli.Config{
		OAuth2Config:           c.oauth2Config,
		State:                  in.State,
		AuthCodeOptions:        authorizationRequestOptions(in.Nonce, in.PKCEParams, in.AuthRequestExtraParams),
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
	opts := authorizationRequestOptions(in.Nonce, in.PKCEParams, in.AuthRequestExtraParams)
	return c.oauth2Config.AuthCodeURL(in.State, opts...)
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

func authorizationRequestOptions(nonce string, pkceParams pkce.Params, extraParams map[string]string) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		gooidc.Nonce(nonce),
	}
	if pkceOpt := pkceParams.AuthCodeOption(); pkceOpt != nil {
		opts = append(opts, pkceOpt)
	}
	for key, value := range extraParams {
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

func (c *client) NegotiatedPKCEMethod() pkce.Method {
	return c.negotiatedPKCEMethod
}

// GetTokenByROPC performs the resource owner password credentials flow.
func (c *client) GetTokenByROPC(ctx context.Context, username, password string) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	token, err := c.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("resource owner password credentials flow error: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}

// GetTokenByClientCredentials performs the client credentials flow.
func (c *client) GetTokenByClientCredentials(ctx context.Context, in GetTokenByClientCredentialsInput) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	c.logger.V(1).Infof("%s, %s, %v", c.oauth2Config.ClientID, c.oauth2Config.Endpoint.AuthURL, c.oauth2Config.Scopes)

	config := clientcredentials.Config{
		ClientID:       c.oauth2Config.ClientID,
		ClientSecret:   c.oauth2Config.ClientSecret,
		TokenURL:       c.oauth2Config.Endpoint.TokenURL,
		Scopes:         c.oauth2Config.Scopes,
		EndpointParams: in.EndpointParams,
		AuthStyle:      oauth2.AuthStyleInHeader,
	}
	source := config.TokenSource(ctx)
	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("could not acquire token: %w", err)
	}
	if c.useAccessToken {
		return &oidc.TokenSet{
			IDToken:      token.AccessToken,
			RefreshToken: token.RefreshToken}, nil
	}
	return c.verifyToken(ctx, token, "")
}

// GetDeviceAuthorization initializes the device authorization code challenge
func (c *client) GetDeviceAuthorization(ctx context.Context) (*oauth2dev.AuthorizationResponse, error) {
	ctx = c.wrapContext(ctx)
	config := c.oauth2Config
	config.Endpoint = oauth2.Endpoint{
		AuthURL: c.deviceAuthorizationEndpoint,
	}
	return oauth2dev.RetrieveCode(ctx, config)
}

// ExchangeDeviceCode exchanges the device to an oidc.TokenSet
func (c *client) ExchangeDeviceCode(ctx context.Context, authResponse *oauth2dev.AuthorizationResponse) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	tokenResponse, err := oauth2dev.PollToken(ctx, c.oauth2Config, *authResponse)
	if err != nil {
		return nil, fmt.Errorf("device-code: exchange failed: %w", err)
	}
	return c.verifyToken(ctx, tokenResponse, "")
}

// Refresh sends a refresh token request and returns a token set.
func (c *client) Refresh(ctx context.Context, refreshToken string) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	currentToken := &oauth2.Token{
		Expiry:       time.Now(),
		RefreshToken: refreshToken,
	}
	source := c.oauth2Config.TokenSource(ctx, currentToken)
	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("could not refresh the token: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}

// verifyToken verifies the token with the certificates of the provider and the nonce.
// If the nonce is an empty string, it does not verify the nonce.
func (c *client) verifyToken(ctx context.Context, token *oauth2.Token, nonce string) (*oidc.TokenSet, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("id_token is missing in the token response: %#v", token)
	}
	verifier := c.provider.Verifier(&gooidc.Config{ClientID: c.oauth2Config.ClientID, Now: c.clock.Now})
	verifiedIDToken, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify the ID token: %w", err)
	}
	if nonce != "" && nonce != verifiedIDToken.Nonce {
		return nil, fmt.Errorf("nonce did not match (wants %s but got %s)", nonce, verifiedIDToken.Nonce)
	}

	if c.useAccessToken {
		accessToken, ok := token.Extra("access_token").(string)
		if !ok {
			return nil, fmt.Errorf("access_token is missing in the token response: %#v", accessToken)
		}

		// We intentionally do not perform a ClientID check here because there
		// are some use cases in access_tokens where we *expect* the audience
		// to differ. For example, one can explicitly set
		// `audience=CLUSTER_CLIENT_ID` as an extra auth parameter.
		verifier = c.provider.Verifier(&gooidc.Config{ClientID: "", Now: c.clock.Now, SkipClientIDCheck: true})

		_, err := verifier.Verify(ctx, accessToken)
		if err != nil {
			return nil, fmt.Errorf("could not verify the access token: %w", err)
		}

		// There is no `nonce` to check on the `access_token`. We rely on the
		// above `nonce` check on the `id_token`.

		return &oidc.TokenSet{
			IDToken:      accessToken,
			RefreshToken: token.RefreshToken,
		}, nil
	}
	return &oidc.TokenSet{
		IDToken:      idToken,
		RefreshToken: token.RefreshToken,
	}, nil
}
