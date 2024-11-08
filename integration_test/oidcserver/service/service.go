package service

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/int128/kubelogin/integration_test/oidcserver/testconfig"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
)

func New(t *testing.T, issuerURL string, config testconfig.TestConfig) Service {
	return &server{
		config:    config,
		t:         t,
		issuerURL: issuerURL,
	}
}

type server struct {
	config                    testconfig.TestConfig
	t                         *testing.T
	issuerURL                 string
	lastAuthenticationRequest *AuthenticationRequest
	lastTokenResponse         *TokenResponse
}

func (sv *server) IssuerURL() string {
	return sv.issuerURL
}

func (sv *server) SetConfig(cfg testconfig.TestConfig) {
	sv.config = cfg
}

func (sv *server) LastTokenResponse() *TokenResponse {
	return sv.lastTokenResponse
}

func (sv *server) Discovery() *DiscoveryResponse {
	// based on https://accounts.google.com/.well-known/openid-configuration
	return &DiscoveryResponse{
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
		CodeChallengeMethodsSupported:     sv.config.Response.CodeChallengeMethodsSupported,
		ClaimsSupported:                   []string{"aud", "email", "exp", "iat", "iss", "name", "sub"},
	}
}

func (sv *server) GetCertificates() *CertificatesResponse {
	idTokenKeyPair := testingJWT.PrivateKey
	return &CertificatesResponse{
		Keys: []*CertificatesResponseKey{
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

func (sv *server) AuthenticateCode(req AuthenticationRequest) (code string, err error) {
	if req.Scope != sv.config.Want.Scope {
		sv.t.Errorf("scope wants `%s` but was `%s`", sv.config.Want.Scope, req.Scope)
	}
	if !strings.HasPrefix(req.RedirectURI, sv.config.Want.RedirectURIPrefix) {
		sv.t.Errorf("redirectURI wants prefix `%s` but was `%s`", sv.config.Want.RedirectURIPrefix, req.RedirectURI)
	}
	if req.CodeChallengeMethod != sv.config.Want.CodeChallengeMethod {
		sv.t.Errorf("code_challenge_method wants `%s` but was `%s`", sv.config.Want.CodeChallengeMethod, req.CodeChallengeMethod)
	}
	for k, v := range sv.config.Want.ExtraParams {
		got := req.RawQuery.Get(k)
		if got != v {
			sv.t.Errorf("parameter %s wants `%s` but was `%s`", k, v, got)
		}
	}
	sv.lastAuthenticationRequest = &req
	return "YOUR_AUTH_CODE", nil
}

func (sv *server) Exchange(req TokenRequest) (*TokenResponse, error) {
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
	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: sv.config.Response.RefreshToken,
		IDToken: testingJWT.EncodeF(sv.t, func(claims *testingJWT.Claims) {
			claims.Issuer = sv.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = jwt.NewNumericDate(sv.config.Response.IDTokenExpiry.Add(-time.Hour))
			claims.ExpiresAt = jwt.NewNumericDate(sv.config.Response.IDTokenExpiry)
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

func (sv *server) AuthenticatePassword(username, password, scope string) (*TokenResponse, error) {
	if scope != sv.config.Want.Scope {
		sv.t.Errorf("scope wants `%s` but was `%s`", sv.config.Want.Scope, scope)
	}
	if username != sv.config.Want.Username {
		sv.t.Errorf("username wants `%s` but was `%s`", sv.config.Want.Username, username)
	}
	if password != sv.config.Want.Password {
		sv.t.Errorf("password wants `%s` but was `%s`", sv.config.Want.Password, password)
	}
	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: sv.config.Response.RefreshToken,
		IDToken: testingJWT.EncodeF(sv.t, func(claims *testingJWT.Claims) {
			claims.Issuer = sv.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = jwt.NewNumericDate(sv.config.Response.IDTokenExpiry.Add(-time.Hour))
			claims.ExpiresAt = jwt.NewNumericDate(sv.config.Response.IDTokenExpiry)
			claims.Audience = []string{"kubernetes"}
		}),
	}
	sv.lastTokenResponse = resp
	return resp, nil
}

func (sv *server) Refresh(refreshToken string) (*TokenResponse, error) {
	if refreshToken != sv.config.Want.RefreshToken {
		sv.t.Errorf("refreshToken wants %s but was %s", sv.config.Want.RefreshToken, refreshToken)
	}
	if sv.config.Response.RefreshError != "" {
		return nil, &ErrorResponse{Code: "invalid_request", Description: sv.config.Response.RefreshError}
	}
	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: sv.config.Response.RefreshToken,
		IDToken: testingJWT.EncodeF(sv.t, func(claims *testingJWT.Claims) {
			claims.Issuer = sv.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = jwt.NewNumericDate(sv.config.Response.IDTokenExpiry.Add(-time.Hour))
			claims.ExpiresAt = jwt.NewNumericDate(sv.config.Response.IDTokenExpiry)
			claims.Audience = []string{"kubernetes"}
		}),
	}
	sv.lastTokenResponse = resp
	return resp, nil
}
