package kubeconfig

import (
	"strings"

	"golang.org/x/xerrors"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func (*Kubeconfig) GetCurrentAuthProvider(explicitFilename string, contextName ContextName, userName UserName) (*AuthProvider, error) {
	config, err := loadByDefaultRules(explicitFilename)
	if err != nil {
		return nil, xerrors.Errorf("could not load the kubeconfig: %w", err)
	}
	auth, err := findCurrentAuthProvider(config, contextName, userName)
	if err != nil {
		return nil, xerrors.Errorf("could not find the current auth provider: %w", err)
	}
	return auth, nil
}

func loadByDefaultRules(explicitFilename string) (*api.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = explicitFilename
	config, err := rules.Load()
	if err != nil {
		return nil, xerrors.Errorf("load error: %w", err)
	}
	return config, err
}

// findCurrentAuthProvider resolves the current auth provider.
// If contextName is given, this returns the user of the context.
// If userName is given, this ignores the context and returns the user.
// If any context or user is not found, this returns an error.
func findCurrentAuthProvider(config *api.Config, contextName ContextName, userName UserName) (*AuthProvider, error) {
	if userName == "" {
		if contextName == "" {
			contextName = ContextName(config.CurrentContext)
		}
		contextNode, ok := config.Contexts[string(contextName)]
		if !ok {
			return nil, xerrors.Errorf("context %s does not exist", contextName)
		}
		userName = UserName(contextNode.AuthInfo)
	}
	userNode, ok := config.AuthInfos[string(userName)]
	if !ok {
		return nil, xerrors.Errorf("user %s does not exist", userName)
	}
	if userNode.AuthProvider == nil {
		return nil, xerrors.New("auth-provider is missing")
	}
	if userNode.AuthProvider.Name != "oidc" {
		return nil, xerrors.Errorf("auth-provider.name must be oidc but is %s", userNode.AuthProvider.Name)
	}
	if userNode.AuthProvider.Config == nil {
		return nil, xerrors.New("auth-provider.config is missing")
	}

	m := userNode.AuthProvider.Config
	var extraScopes []string
	if m["extra-scopes"] != "" {
		extraScopes = strings.Split(m["extra-scopes"], ",")
	}
	return &AuthProvider{
		LocationOfOrigin:            userNode.LocationOfOrigin,
		UserName:                    userName,
		ContextName:                 contextName,
		IDPIssuerURL:                m["idp-issuer-url"],
		ClientID:                    m["client-id"],
		ClientSecret:                m["client-secret"],
		IDPCertificateAuthority:     m["idp-certificate-authority"],
		IDPCertificateAuthorityData: m["idp-certificate-authority-data"],
		ExtraScopes:                 extraScopes,
		IDToken:                     m["id-token"],
		RefreshToken:                m["refresh-token"],
	}, nil
}
