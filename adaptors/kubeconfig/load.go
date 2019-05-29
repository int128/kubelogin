package kubeconfig

import (
	"strings"

	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func (*Kubeconfig) GetCurrentAuth(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.Auth, error) {
	config, err := loadByDefaultRules(explicitFilename)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	auth, err := findCurrentAuth(config, contextName, userName)
	if err != nil {
		return nil, errors.Wrapf(err, "could not find the current auth provider")
	}
	return auth, nil
}

func loadByDefaultRules(explicitFilename string) (*api.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = explicitFilename
	config, err := rules.Load()
	if err != nil {
		return nil, errors.Wrapf(err, "could not load the kubeconfig")
	}
	return config, err
}

// findCurrentAuth resolves the current auth provider.
// If contextName is given, this returns the user of the context.
// If userName is given, this ignores the context and returns the user.
// If any context or user is not found, this returns an error.
func findCurrentAuth(config *api.Config, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.Auth, error) {
	if userName == "" {
		if contextName == "" {
			contextName = kubeconfig.ContextName(config.CurrentContext)
		}
		contextNode, ok := config.Contexts[string(contextName)]
		if !ok {
			return nil, errors.Errorf("context %s does not exist", contextName)
		}
		userName = kubeconfig.UserName(contextNode.AuthInfo)
	}
	userNode, ok := config.AuthInfos[string(userName)]
	if !ok {
		return nil, errors.Errorf("user %s does not exist", userName)
	}
	if userNode.AuthProvider == nil {
		return nil, errors.Errorf("auth-provider is missing")
	}
	if userNode.AuthProvider.Name != "oidc" {
		return nil, errors.Errorf("auth-provider.name must be oidc but is %s", userNode.AuthProvider.Name)
	}
	if userNode.AuthProvider.Config == nil {
		return nil, errors.Errorf("auth-provider.config is missing")
	}
	return &kubeconfig.Auth{
		LocationOfOrigin: userNode.LocationOfOrigin,
		UserName:         userName,
		ContextName:      contextName,
		OIDCConfig:       makeOIDCConfig(userNode.AuthProvider.Config),
	}, nil
}

func makeOIDCConfig(m map[string]string) kubeconfig.OIDCConfig {
	var extraScopes []string
	if m["extra-scopes"] != "" {
		extraScopes = strings.Split(m["extra-scopes"], ",")
	}
	return kubeconfig.OIDCConfig{
		IDPIssuerURL:                m["idp-issuer-url"],
		ClientID:                    m["client-id"],
		ClientSecret:                m["client-secret"],
		IDPCertificateAuthority:     m["idp-certificate-authority"],
		IDPCertificateAuthorityData: m["idp-certificate-authority-data"],
		ExtraScopes:                 extraScopes,
		IDToken:                     m["id-token"],
		RefreshToken:                m["refresh-token"],
	}
}
