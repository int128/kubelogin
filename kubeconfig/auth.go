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

func ToOIDCAuthProviderConfig(authInfo *api.AuthInfo) (*OIDCAuthProviderConfig, error) {
	if authInfo.AuthProvider == nil {
		return nil, fmt.Errorf("auth-provider is not set")
	}
	if authInfo.AuthProvider.Name != "oidc" {
		return nil, fmt.Errorf("auth-provider `%s` is not supported", authInfo.AuthProvider.Name)
	}
	return (*OIDCAuthProviderConfig)(authInfo.AuthProvider), nil
}

type OIDCAuthProviderConfig api.AuthProviderConfig

// IDPIssuerURL returns the idp-issuer-url.
func (c *OIDCAuthProviderConfig) IDPIssuerURL() string {
	return c.Config["idp-issuer-url"]
}

// ClientID returns the client-id.
func (c *OIDCAuthProviderConfig) ClientID() string {
	return c.Config["client-id"]
}

// ClientSecret returns the client-secret.
func (c *OIDCAuthProviderConfig) ClientSecret() string {
	return c.Config["client-secret"]
}

func (c *OIDCAuthProviderConfig) SetIDToken(idToken string) {
	c.Config["id-token"] = idToken
}

func (c *OIDCAuthProviderConfig) SetRefreshToken(refreshToken string) {
	c.Config["refresh-token"] = refreshToken
}
