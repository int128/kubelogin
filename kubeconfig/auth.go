package kubeconfig

import (
	"fmt"

	"k8s.io/client-go/tools/clientcmd/api"
)

// FindCurrentAuthInfo returns the authInfo of current context.
// If the current context does not exist, this returns nil.
func FindCurrentAuthInfo(config *api.Config) *api.AuthInfo {
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		return nil
	}
	return config.AuthInfos[context.AuthInfo]
}

// FindOIDCAuthProvider returns the OIDC authProvider.
func FindOIDCAuthProvider(authInfo *api.AuthInfo) (*OIDCAuthProvider, error) {
	if authInfo.AuthProvider == nil {
		return nil, fmt.Errorf("auth-provider is not set, did you setup kubectl as listed here: https://github.com/int128/kubelogin")
	}
	if authInfo.AuthProvider.Name != "oidc" {
		return nil, fmt.Errorf("auth-provider `%s` is not supported", authInfo.AuthProvider.Name)
	}
	return (*OIDCAuthProvider)(authInfo.AuthProvider), nil
}

// OIDCAuthProvider represents OIDC configuration in the kubeconfig.
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

// SetIDToken replaces the id-token.
func (c *OIDCAuthProvider) SetIDToken(idToken string) {
	c.Config["id-token"] = idToken
}

// SetRefreshToken replaces the refresh-token.
func (c *OIDCAuthProvider) SetRefreshToken(refreshToken string) {
	c.Config["refresh-token"] = refreshToken
}
