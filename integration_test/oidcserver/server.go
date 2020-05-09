// Package oidcserver provides a stub of OpenID Connect provider.
package oidcserver

import (
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/oidcserver/handler"
	"github.com/int128/kubelogin/integration_test/oidcserver/http"
	"github.com/int128/kubelogin/pkg/testing/jwt"
	"golang.org/x/xerrors"
)

type Server interface {
	http.Shutdowner
	IssuerURL() string
	NewTokenResponse(expiry time.Time, nonce string) *handler.TokenResponse
	LastTokenResponse() *handler.TokenResponse
}

// Config represents a configuration of the OpenID Connect provider.
type Config struct {
	TLS           keypair.KeyPair
	IDTokenExpiry time.Time
	RefreshError  string // if set, Refresh() will return the error

	// expected values
	Scope             string
	RedirectURIPrefix string
	ExtraParams       map[string]string // optional
	Username          string            // optional
	Password          string            // optional
	RefreshToken      string            // optional
}

// New starts a HTTP server for the OpenID Connect provider.
func New(t *testing.T, c Config) Server {
	sv := server{Config: c, t: t}
	sv.issuerURL, sv.Shutdowner = http.Start(t, handler.New(t, &sv), c.TLS)
	return &sv
}

type server struct {
	Config
	http.Shutdowner
	t                 *testing.T
	issuerURL         string
	nonce             string
	lastTokenResponse *handler.TokenResponse
}

func (sv *server) IssuerURL() string {
	return sv.issuerURL
}

func (sv *server) NewTokenResponse(expiry time.Time, nonce string) *handler.TokenResponse {
	idToken := jwt.EncodeF(sv.t, func(claims *jwt.Claims) {
		claims.Issuer = sv.IssuerURL()
		claims.Subject = "SUBJECT"
		claims.IssuedAt = expiry.Add(-time.Hour).Unix()
		claims.ExpiresAt = expiry.Unix()
		claims.Audience = []string{"kubernetes", "system"}
		claims.Nonce = nonce
		claims.Groups = []string{"admin", "users"}
	})
	resp := &handler.TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		IDToken:      idToken,
		RefreshToken: "YOUR_REFRESH_TOKEN",
	}
	sv.lastTokenResponse = resp
	return resp
}

func (sv *server) LastTokenResponse() *handler.TokenResponse {
	return sv.lastTokenResponse
}

func (sv *server) Discovery() *handler.DiscoveryResponse {
	// based on https://accounts.google.com/.well-known/openid-configuration
	return &handler.DiscoveryResponse{
		Issuer:                            sv.issuerURL,
		AuthorizationEndpoint:             sv.issuerURL + "/auth",
		TokenEndpoint:                     sv.issuerURL + "/token",
		JwksURI:                           sv.issuerURL + "/certs",
		UserinfoEndpoint:                  sv.issuerURL + "/userinfo",
		RevocationEndpoint:                sv.issuerURL + "/revoke",
		ResponseTypesSupported:            []string{"code id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "email", "profile"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
		ClaimsSupported:                   []string{"aud", "email", "exp", "iat", "iss", "name", "sub"},
	}
}

func (sv *server) GetCertificates() *handler.CertificatesResponse {
	idTokenKeyPair := jwt.PrivateKey
	return &handler.CertificatesResponse{
		Keys: []*handler.CertificatesResponseKey{
			{
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				Kid: "dummy",
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idTokenKeyPair.E)).Bytes()),
				N:   base64.RawURLEncoding.EncodeToString(idTokenKeyPair.N.Bytes()),
			},
		},
	}
}

func (sv *server) AuthenticateCode(req handler.AuthenticationRequest) (code string, err error) {
	if req.Scope != sv.Scope {
		sv.t.Errorf("scope wants `%s` but was `%s`", sv.Scope, req.Scope)
	}
	if !strings.HasPrefix(req.RedirectURI, sv.RedirectURIPrefix) {
		sv.t.Errorf("redirectURI wants prefix `%s` but was `%s`", sv.RedirectURIPrefix, req.RedirectURI)
	}
	for k, v := range sv.ExtraParams {
		got := req.RawQuery.Get(k)
		if got != v {
			sv.t.Errorf("parameter %s wants `%s` but was `%s`", k, v, got)
		}
	}
	sv.nonce = req.Nonce
	return "YOUR_AUTH_CODE", nil
}

func (sv *server) Exchange(code string) (*handler.TokenResponse, error) {
	if code != "YOUR_AUTH_CODE" {
		return nil, xerrors.Errorf("code wants %s but was %s", "YOUR_AUTH_CODE", code)
	}
	return sv.NewTokenResponse(sv.IDTokenExpiry, sv.nonce), nil
}

func (sv *server) AuthenticatePassword(username, password, scope string) (*handler.TokenResponse, error) {
	if scope != sv.Scope {
		sv.t.Errorf("scope wants `%s` but was `%s`", sv.Scope, scope)
	}
	if username != sv.Username {
		sv.t.Errorf("username wants `%s` but was `%s`", sv.Username, username)
	}
	if password != sv.Password {
		sv.t.Errorf("password wants `%s` but was `%s`", sv.Password, password)
	}
	return sv.NewTokenResponse(sv.IDTokenExpiry, ""), nil
}

func (sv *server) Refresh(refreshToken string) (*handler.TokenResponse, error) {
	if refreshToken != sv.RefreshToken {
		sv.t.Errorf("refreshToken wants %s but was %s", sv.RefreshToken, refreshToken)
	}
	if sv.RefreshError != "" {
		return nil, &handler.ErrorResponse{Code: "invalid_request", Description: sv.RefreshError}
	}
	return sv.NewTokenResponse(sv.IDTokenExpiry, sv.nonce), nil
}
