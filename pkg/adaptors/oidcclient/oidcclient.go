package oidcclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/wire"
	"github.com/pipedrive/kubelogin/pkg/adaptors/logger"
	"github.com/pipedrive/oauth2cli"
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
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	CodeVerifier        string
}

// TokenSet represents an output DTO of
// Interface.GetTokenByAuthCode, Interface.GetTokenByROPC and Interface.Refresh.
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

// GetTokenByAuthCode performs the authorization code flow.
func (c *client) GetTokenByAuthCode(ctx context.Context, in GetTokenByAuthCodeInput, localServerReadyChan chan<- string) (*TokenSet, error) {

	ctx = c.wrapContext(ctx)

	config := oauth2cli.Config{
		OAuth2Config: c.oauth2Config,
		AuthCodeOptions: []oauth2.AuthCodeOption{
			oauth2.AccessTypeOnline,
			oidc.Nonce(in.Nonce),
			oauth2.SetAuthURLParam("code_challenge", in.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", in.CodeChallengeMethod),
			oauth2.SetAuthURLParam("response_type", "id_token"),
			oauth2.SetAuthURLParam("response_mode", "form_post"),
		},
		TokenRequestOptions: []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("code_verifier", in.CodeVerifier),
		},
		LocalServerBindAddress: in.BindAddress,
		LocalServerReadyChan:   localServerReadyChan,
	}

	token, err := oauth2cli.GetToken(ctx, config)
	if err != nil {
		return nil, xerrors.Errorf("could not get a token: %w", err)
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
	id_token := token.AccessToken
	if err != nil {
		return nil, xerrors.Errorf("could not exchange the authorization code: %w", err)
	}
	return c.verifyToken(ctx, id_token, in.Nonce)
}

// GetTokenByROPC performs the resource owner password credentials flow.
func (c *client) GetTokenByROPC(ctx context.Context, username, password string) (*TokenSet, error) {
	ctx = c.wrapContext(ctx)
	token, err := c.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, xerrors.Errorf("could not get a token: %w", err)
	}
	return c.verifyToken(ctx, token.AccessToken, "")
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
	return c.verifyToken(ctx, token.AccessToken, "")
}

// verifyToken verifies the token with the certificates of the provider and the nonce.
// If the nonce is an empty string, it does not verify the nonce.
func (c *client) verifyToken(ctx context.Context, idTokenString string, nonce string) (*TokenSet, error) {
	verifier := c.provider.Verifier(&oidc.Config{ClientID: c.oauth2Config.ClientID})
	idToken, err := verifier.Verify(ctx, idTokenString)
	if err != nil {
		return nil, xerrors.Errorf("could not verify the ID token: %w", err)
	}
	if nonce != "" && nonce != idToken.Nonce {
		return nil, xerrors.Errorf("nonce did not match (wants %s but was %s)", nonce, idToken.Nonce)
	}
	claims, err := dumpClaims(idToken)
	if err != nil {
		c.logger.V(1).Infof("incomplete claims of the ID token: %w", err)
	}
	return &TokenSet{
		IDToken:       idTokenString,
		IDTokenExpiry: idToken.Expiry,
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
