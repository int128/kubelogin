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
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/integration_test/oidcserver/testconfig"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
)

func New(t *testing.T, issuerURL string, config testconfig.Config) Service {
	return &service{
		config:    config,
		t:         t,
		issuerURL: issuerURL,
	}
}

type service struct {
	config                    testconfig.Config
	t                         *testing.T
	issuerURL                 string
	lastAuthenticationRequest *AuthenticationRequest
	lastTokenResponse         *TokenResponse
}

func (svc *service) IssuerURL() string {
	return svc.issuerURL
}

func (svc *service) SetConfig(cfg testconfig.Config) {
	svc.config = cfg
}

func (svc *service) LastTokenResponse() *TokenResponse {
	return svc.lastTokenResponse
}

func (svc *service) Discovery() *DiscoveryResponse {
	// based on https://accounts.google.com/.well-known/openid-configuration
	return &DiscoveryResponse{
		Issuer:                            svc.issuerURL,
		AuthorizationEndpoint:             svc.issuerURL + "/auth",
		TokenEndpoint:                     svc.issuerURL + "/token",
		JwksURI:                           svc.issuerURL + "/certs",
		UserinfoEndpoint:                  svc.issuerURL + "/userinfo",
		RevocationEndpoint:                svc.issuerURL + "/revoke",
		ResponseTypesSupported:            []string{"code id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "email", "profile"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported:     svc.config.Response.CodeChallengeMethodsSupported,
		ClaimsSupported:                   []string{"aud", "email", "exp", "iat", "iss", "name", "sub"},
	}
}

func (svc *service) GetCertificates() *CertificatesResponse {
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

func (svc *service) AuthenticateCode(req AuthenticationRequest) (code string, err error) {
	if req.Scope != svc.config.Want.Scope {
		svc.t.Errorf("scope wants `%s` but was `%s`", svc.config.Want.Scope, req.Scope)
	}
	if !strings.HasPrefix(req.RedirectURI, svc.config.Want.RedirectURIPrefix) {
		svc.t.Errorf("redirectURI wants prefix `%s` but was `%s`", svc.config.Want.RedirectURIPrefix, req.RedirectURI)
	}
	if diff := cmp.Diff(svc.config.Want.CodeChallengeMethod, req.CodeChallengeMethod); diff != "" {
		svc.t.Errorf("code_challenge_method mismatch (-want +got):\n%s", diff)
	}
	for k, v := range svc.config.Want.ExtraParams {
		got := req.RawQuery.Get(k)
		if got != v {
			svc.t.Errorf("parameter %s wants `%s` but was `%s`", k, v, got)
		}
	}
	svc.lastAuthenticationRequest = &req
	return "YOUR_AUTH_CODE", nil
}

func (svc *service) Exchange(req TokenRequest) (*TokenResponse, error) {
	if req.Code != "YOUR_AUTH_CODE" {
		return nil, fmt.Errorf("code wants %s but was %s", "YOUR_AUTH_CODE", req.Code)
	}
	if svc.lastAuthenticationRequest.CodeChallengeMethod == "S256" {
		// https://tools.ietf.org/html/rfc7636#section-4.6
		challenge := computeS256Challenge(req.CodeVerifier)
		if challenge != svc.lastAuthenticationRequest.CodeChallenge {
			svc.t.Errorf("pkce S256 challenge did not match (want %s but was %s)", svc.lastAuthenticationRequest.CodeChallenge, challenge)
		}
	}
	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: svc.config.Response.RefreshToken,
		IDToken: testingJWT.EncodeF(svc.t, func(claims *testingJWT.Claims) {
			claims.Issuer = svc.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry.Add(-time.Hour))
			claims.ExpiresAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry)
			claims.Audience = []string{"kubernetes"}
			claims.Nonce = svc.lastAuthenticationRequest.Nonce
		}),
	}
	svc.lastTokenResponse = resp
	return resp, nil
}

func computeS256Challenge(verifier string) string {
	c := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(c[:])
}

func (svc *service) AuthenticatePassword(username, password, scope string) (*TokenResponse, error) {
	if scope != svc.config.Want.Scope {
		svc.t.Errorf("scope wants `%s` but was `%s`", svc.config.Want.Scope, scope)
	}
	if username != svc.config.Want.Username {
		svc.t.Errorf("username wants `%s` but was `%s`", svc.config.Want.Username, username)
	}
	if password != svc.config.Want.Password {
		svc.t.Errorf("password wants `%s` but was `%s`", svc.config.Want.Password, password)
	}
	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: svc.config.Response.RefreshToken,
		IDToken: testingJWT.EncodeF(svc.t, func(claims *testingJWT.Claims) {
			claims.Issuer = svc.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry.Add(-time.Hour))
			claims.ExpiresAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry)
			claims.Audience = []string{"kubernetes"}
		}),
	}
	svc.lastTokenResponse = resp
	return resp, nil
}

func (svc *service) AuthenticateTokenExchange(req TokenExchangeRequest) (*TokenResponse, error) {
	if req.SubjectToken == "" {
		return nil, &ErrorResponse{Code: "invalid_request", Description: "subject_token is required"}
	}
	if req.SubjectTokenType == "" {
		return nil, &ErrorResponse{Code: "invalid_request", Description: "subject_token_type is required"}
	}
	if req.ActorToken != "" && req.ActorTokenType == "" {
		return nil, &ErrorResponse{Code: "invalid_request", Description: "actor_token_type is required when actor_token is set"}
	}
	if req.ActorToken == "" && req.ActorTokenType != "" {
		return nil, &ErrorResponse{Code: "invalid_request", Description: "actor_token_type must not be set when actor_token is not set"}
	}
	if svc.config.Want.SubjectToken != "" && req.SubjectToken != svc.config.Want.SubjectToken {
		svc.t.Errorf("subject_token wants `%s` but was `%s`", svc.config.Want.SubjectToken, req.SubjectToken)
	}
	if svc.config.Want.SubjectTokenType != "" && req.SubjectTokenType != svc.config.Want.SubjectTokenType {
		svc.t.Errorf("subject_token_type wants `%s` but was `%s`", svc.config.Want.SubjectTokenType, req.SubjectTokenType)
	}
	if svc.config.Want.Scope != "" && req.Scope != svc.config.Want.Scope {
		svc.t.Errorf("scope wants `%s` but was `%s`", svc.config.Want.Scope, req.Scope)
	}
	issuedTokenType := req.RequestTokenType
	if issuedTokenType == "" {
		issuedTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	resp := &TokenResponse{
		AccessToken:     "YOUR_ACCESS_TOKEN",
		IssuedTokenType: issuedTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       3600,

		// RFC 8693 §2.2.1: A refresh token will typically not be issued when
		// the exchange is of one temporary credential (the subject_token) for
		// a different temporary credential (the issued token) ...
		RefreshToken: "",
		IDToken: testingJWT.EncodeF(svc.t, func(claims *testingJWT.Claims) {
			claims.Issuer = svc.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry.Add(-time.Hour))
			claims.ExpiresAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry)
			claims.Audience = []string{"kubernetes"}
		}),
	}
	svc.lastTokenResponse = resp
	return resp, nil
}

func (svc *service) Refresh(refreshToken string) (*TokenResponse, error) {
	if refreshToken != svc.config.Want.RefreshToken {
		svc.t.Errorf("refreshToken wants %s but was %s", svc.config.Want.RefreshToken, refreshToken)
	}
	if svc.config.Response.RefreshError != "" {
		return nil, &ErrorResponse{Code: "invalid_request", Description: svc.config.Response.RefreshError}
	}
	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		RefreshToken: svc.config.Response.RefreshToken,
		IDToken: testingJWT.EncodeF(svc.t, func(claims *testingJWT.Claims) {
			claims.Issuer = svc.issuerURL
			claims.Subject = "SUBJECT"
			claims.IssuedAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry.Add(-time.Hour))
			claims.ExpiresAt = jwt.NewNumericDate(svc.config.Response.IDTokenExpiry)
			claims.Audience = []string{"kubernetes"}
		}),
	}
	svc.lastTokenResponse = resp
	return resp, nil
}
