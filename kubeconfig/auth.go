package kubeconfig

import (
	"strings"

	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd/api"
)

// FindOIDCAuthProvider returns the current OIDC authProvider.
// If the context, auth-info or auth-provider does not exist, this returns an error.
// If auth-provider is not "oidc", this returns an error.
func FindOIDCAuthProvider(config *api.Config) (*OIDCAuthProvider, error) {
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		return nil, errors.Errorf("context %s does not exist", config.CurrentContext)
	}
	authInfo := config.AuthInfos[context.AuthInfo]
	if authInfo == nil {
		return nil, errors.Errorf("auth-info %s does not exist", context.AuthInfo)
	}
	if authInfo.AuthProvider == nil {
		return nil, errors.Errorf("auth-provider is not set")
	}
	if authInfo.AuthProvider.Name != "oidc" {
		return nil, errors.Errorf("auth-provider name is %s but must be oidc", authInfo.AuthProvider.Name)
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
