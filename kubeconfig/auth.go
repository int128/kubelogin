package kubeconfig

import (
	"strings"
)

// OIDCConfig represents config of an oidc auth-provider.
type OIDCConfig map[string]string

// IDPIssuerURL returns the idp-issuer-url.
func (c OIDCConfig) IDPIssuerURL() string {
	return c["idp-issuer-url"]
}

// ClientID returns the client-id.
func (c OIDCConfig) ClientID() string {
	return c["client-id"]
}

// ClientSecret returns the client-secret.
func (c OIDCConfig) ClientSecret() string {
	return c["client-secret"]
}

// IDPCertificateAuthority returns the idp-certificate-authority.
func (c OIDCConfig) IDPCertificateAuthority() string {
	return c["idp-certificate-authority"]
}

// IDPCertificateAuthorityData returns the idp-certificate-authority-data.
func (c OIDCConfig) IDPCertificateAuthorityData() string {
	return c["idp-certificate-authority-data"]
}

// ExtraScopes returns the extra-scopes.
func (c OIDCConfig) ExtraScopes() []string {
	if c["extra-scopes"] == "" {
		return []string{}
	}
	return strings.Split(c["extra-scopes"], ",")
}

// IDToken returns the id-token.
func (c OIDCConfig) IDToken() string {
	return c["id-token"]
}

// SetIDToken replaces the id-token.
func (c OIDCConfig) SetIDToken(idToken string) {
	c["id-token"] = idToken
}

// SetRefreshToken replaces the refresh-token.
func (c OIDCConfig) SetRefreshToken(refreshToken string) {
	c["refresh-token"] = refreshToken
}
