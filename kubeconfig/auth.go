package kubeconfig

import (
	"strings"

	"k8s.io/client-go/tools/clientcmd/api"
)

// OIDCAuthProvider represents an OIDC auth-provider.
type OIDCAuthProvider api.AuthProviderConfig

// IDPIssuerURL returns the idp-issuer-url.
func (c *OIDCAuthProvider) IDPIssuerURL() string {
	return c.Config["idp-issuer-url"]
}

// ClientID returns the client-id.
func (c *OIDCAuthProvider) ClientID() string {
	return c.Config["client-id"]
}

// ClientSecret returns the client-secret.
func (c *OIDCAuthProvider) ClientSecret() string {
	return c.Config["client-secret"]
}

// IDPCertificateAuthority returns the idp-certificate-authority.
func (c *OIDCAuthProvider) IDPCertificateAuthority() string {
	return c.Config["idp-certificate-authority"]
}

// IDPCertificateAuthorityData returns the idp-certificate-authority-data.
func (c *OIDCAuthProvider) IDPCertificateAuthorityData() string {
	return c.Config["idp-certificate-authority-data"]
}

// ExtraScopes returns the extra-scopes.
func (c *OIDCAuthProvider) ExtraScopes() []string {
	if c.Config["extra-scopes"] == "" {
		return []string{}
	}
	return strings.Split(c.Config["extra-scopes"], ",")
}

// IDToken returns the id-token.
func (c *OIDCAuthProvider) IDToken() string {
	return c.Config["id-token"]
}

// SetIDToken replaces the id-token.
func (c *OIDCAuthProvider) SetIDToken(idToken string) {
	c.Config["id-token"] = idToken
}

// SetRefreshToken replaces the refresh-token.
func (c *OIDCAuthProvider) SetRefreshToken(refreshToken string) {
	c.Config["refresh-token"] = refreshToken
}
