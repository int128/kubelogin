// Package idp provides a test double of an OpenID Connect Provider.
package idp

//go:generate mockgen -destination mock_idp/mock_idp.go github.com/int128/kubelogin/integration_test/idp Provider

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
)

// Provider provides discovery and authentication methods.
// If an implemented method returns an ErrorResponse,
// the handler will respond 400 and corresponding json of the ErrorResponse.
// Otherwise, the handler will respond 500 and fail the current test.
type Provider interface {
	Discovery() *DiscoveryResponse
	GetCertificates() *CertificatesResponse
	AuthenticateCode(req AuthenticationRequest) (code string, err error)
	Exchange(code string) (*TokenResponse, error)
	AuthenticatePassword(username, password, scope string) (*TokenResponse, error)
	Refresh(refreshToken string) (*TokenResponse, error)
}

type DiscoveryResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// NewDiscoveryResponse returns a DiscoveryResponse for the local server.
// This is based on https://accounts.google.com/.well-known/openid-configuration.
func NewDiscoveryResponse(issuer string) *DiscoveryResponse {
	return &DiscoveryResponse{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/auth",
		TokenEndpoint:                     issuer + "/token",
		JwksURI:                           issuer + "/certs",
		UserinfoEndpoint:                  issuer + "/userinfo",
		RevocationEndpoint:                issuer + "/revoke",
		ResponseTypesSupported:            []string{"code id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "email", "profile"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
		ClaimsSupported:                   []string{"aud", "email", "exp", "iat", "iss", "name", "sub"},
	}
}

type CertificatesResponse struct {
	Keys []*CertificatesResponseKey `json:"keys"`
}

type CertificatesResponseKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewCertificatesResponse returns a CertificatesResponse using the key pair.
// This is used for verifying a signature of ID token.
func NewCertificatesResponse(idTokenKeyPair *rsa.PrivateKey) *CertificatesResponse {
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

type AuthenticationRequest struct {
	RedirectURI string
	State       string
	Scope       string // space separated string
	Nonce       string
	RawQuery    url.Values
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

// NewTokenResponse returns a TokenResponse.
func NewTokenResponse(idToken, refreshToken string) *TokenResponse {
	return &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		AccessToken:  "YOUR_ACCESS_TOKEN",
		IDToken:      idToken,
		RefreshToken: refreshToken,
	}
}

// ErrorResponse represents an error response described in the following section:
// 5.2 Error Response
// https://tools.ietf.org/html/rfc6749#section-5.2
type ErrorResponse struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (err *ErrorResponse) Error() string {
	return fmt.Sprintf("%s(%s)", err.Code, err.Description)
}
