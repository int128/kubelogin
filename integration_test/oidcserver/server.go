// Package oidcserver provides a stub of OpenID Connect provider.
package oidcserver

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/oidcserver/handler"
	"github.com/int128/kubelogin/integration_test/oidcserver/http"
	"github.com/int128/kubelogin/pkg/testing/jwt"
)

type Server interface {
	IssuerURL() string
	SetConfig(Config)
	LastTokenResponse() *handler.TokenResponse
}

// Want represents a set of expected values.
type Want struct {
	Scope               string
	RedirectURIPrefix   string
	CodeChallengeMethod string            // optional
	ExtraParams         map[string]string // optional
	Username            string            // optional
	Password            string            // optional
	RefreshToken        string            // optional
}

// Response represents a set of response values.
type Response struct {
	IDTokenExpiry                 time.Time
	RefreshToken                  string
	RefreshError                  string   // if set, Refresh() will return the error
	CodeChallengeMethodsSupported []string // optional
}

// Config represents a configuration of the OpenID Connect provider.
type Config struct {
	Want     Want
	Response Response
}

// New starts a HTTP server for the OpenID Connect provider.
func New(t *testing.T, k keypair.KeyPair, c Config) Server {
	sv := server{Config: c, t: t}
	sv.issuerURL = http.Start(t, handler.New(t, &sv), k)
	return &sv
}

type server struct {
	Config
	t                         *testing.T
	issuerURL                 string
	lastAuthenticationRequest *handler.AuthenticationRequest
	lastTokenResponse         *handler.TokenResponse
}

func (sv *server) IssuerURL() string {
	return sv.issuerURL
}

func (sv *server) SetConfig(cfg Config) {
	sv.Config = cfg
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
		CodeChallengeMethodsSupported:     sv.Config.Response.CodeChallengeMethodsSupported,
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
	if req.Scope != sv.Want.Scope {
		sv.t.Errorf("scope wants `%s` but was `%s`", sv.Want.Scope, req.Scope)
	}
	if !strings.HasPrefix(req.RedirectURI, sv.Want.RedirectURIPrefix) {
		sv.t.Errorf("redirectURI wants prefix `%s` but was `%s`", sv.Want.RedirectURIPrefix, req.RedirectURI)
	}
	if req.CodeChallengeMethod != sv.Want.CodeChallengeMethod {
		sv.t.Errorf("code_challenge_method wants `%s` but was `%s`", sv.Want.CodeChallengeMethod, req.CodeChallengeMethod)
	}
	for k, v := range sv.Want.ExtraParams {
		got := req.RawQuery.Get(k)
		if got != v {
			sv.t.Errorf("parameter %s wants `%s` but was `%s`", k, v, got)
		}
	}
	sv.lastAuthenticationRequest = &req
	return "YOUR_AUTH_CODE", nil
}

func (sv *server) Exchange(req handler.TokenRequest) (*handler.TokenResponse, error) {
	if req.Code != "YOUR_AUTH_CODE" {
		return nil, fmt.Errorf("code wants %s but was %s", "YOUR_AUTH_CODE", req.Code)
	}
	if sv.lastAuthenticationRequest.CodeChallengeMethod == "S256" {
		// https://tools.ietf.org/html/rfc7636#section-4.6
		challenge := computeS256Challenge(req.CodeVerifier)
		if challenge != sv.lastAuthenticationRequest.CodeChallenge {
			sv.t.Errorf("pkce S256 challenge did not match (want %s but was %s)", sv.lastAuthenticationRequest.CodeChallenge, challenge)
		}
	}
	resp := &handler.TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: sv.Response.RefreshToken,
		IDToken: jwt.EncodeF(sv.t, func(claims *jwt.Claims) {
			claims.Issuer = sv.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = sv.Response.IDTokenExpiry.Add(-time.Hour).Unix()
			claims.ExpiresAt = sv.Response.IDTokenExpiry.Unix()
			claims.Audience = []string{"kubernetes"}
			claims.Nonce = sv.lastAuthenticationRequest.Nonce
		}),
	}
	sv.lastTokenResponse = resp
	return resp, nil
}

func computeS256Challenge(verifier string) string {
	c := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(c[:])
}

func (sv *server) AuthenticatePassword(username, password, scope string) (*handler.TokenResponse, error) {
	if scope != sv.Want.Scope {
		sv.t.Errorf("scope wants `%s` but was `%s`", sv.Want.Scope, scope)
	}
	if username != sv.Want.Username {
		sv.t.Errorf("username wants `%s` but was `%s`", sv.Want.Username, username)
	}
	if password != sv.Want.Password {
		sv.t.Errorf("password wants `%s` but was `%s`", sv.Want.Password, password)
	}
	resp := &handler.TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: sv.Response.RefreshToken,
		IDToken: jwt.EncodeF(sv.t, func(claims *jwt.Claims) {
			claims.Issuer = sv.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = sv.Response.IDTokenExpiry.Add(-time.Hour).Unix()
			claims.ExpiresAt = sv.Response.IDTokenExpiry.Unix()
			claims.Audience = []string{"kubernetes"}
		}),
	}
	sv.lastTokenResponse = resp
	return resp, nil
}

func (sv *server) Refresh(refreshToken string) (*handler.TokenResponse, error) {
	if refreshToken != sv.Want.RefreshToken {
		sv.t.Errorf("refreshToken wants %s but was %s", sv.Want.RefreshToken, refreshToken)
	}
	if sv.Response.RefreshError != "" {
		return nil, &handler.ErrorResponse{Code: "invalid_request", Description: sv.Response.RefreshError}
	}
	resp := &handler.TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: sv.Response.RefreshToken,
		IDToken: jwt.EncodeF(sv.t, func(claims *jwt.Claims) {
			claims.Issuer = sv.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = sv.Response.IDTokenExpiry.Add(-time.Hour).Unix()
			claims.ExpiresAt = sv.Response.IDTokenExpiry.Unix()
			claims.Audience = []string{"kubernetes"}
		}),
	}
	sv.lastTokenResponse = resp
	return resp, nil
}
