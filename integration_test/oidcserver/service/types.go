package service

import (
	"fmt"
	"net/url"

	"github.com/int128/kubelogin/integration_test/oidcserver/testconfig"
)

// Service represents the test service of OpenID Connect Provider.
// It provides the feature of Provider and additional methods for testing.
type Service interface {
	Provider

	IssuerURL() string
	SetConfig(config testconfig.Config)
	LastTokenResponse() *TokenResponse
}

// Provider represents an OpenID Connect Provider.
//
// If an implemented method returns an ErrorResponse,
// the handler will respond 400 and corresponding json of the ErrorResponse.
// Otherwise, the handler will respond 500 and fail the current test.
type Provider interface {
	Discovery() *DiscoveryResponse
	GetCertificates() *CertificatesResponse
	AuthenticateCode(req AuthenticationRequest) (code string, err error)
	Exchange(req TokenRequest) (*TokenResponse, error)
	AuthenticatePassword(username, password, scope string) (*TokenResponse, error)
	Refresh(refreshToken string) (*TokenResponse, error)
}

// DiscoveryResponse represents the type of:
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
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

// CertificatesResponse represents the type of:
// https://datatracker.ietf.org/doc/html/rfc7517#section-5
type CertificatesResponse struct {
	Keys []*CertificatesResponseKey `json:"keys"`
}

// CertificatesResponseKey represents the type of:
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type CertificatesResponseKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// AuthenticationRequest represents the type of:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthenticationRequest struct {
	RedirectURI         string
	State               string
	Scope               string // space separated string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	RawQuery            url.Values
}

// TokenRequest represents the type of:
// https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
type TokenRequest struct {
	Code         string
	CodeVerifier string
}

// TokenResponse represents the type of:
// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

// ErrorResponse represents the error response described in the following section:
// 5.2 Error Response
// https://tools.ietf.org/html/rfc6749#section-5.2
type ErrorResponse struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (err *ErrorResponse) Error() string {
	return fmt.Sprintf("%s(%s)", err.Code, err.Description)
}
