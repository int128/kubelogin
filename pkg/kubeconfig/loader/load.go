package loader

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/kubeconfig"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var Set = wire.NewSet(
	wire.Struct(new(Loader), "*"),
	wire.Bind(new(Interface), new(*Loader)),
)

type Interface interface {
	GetCurrentAuthProvider(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error)
}

type Loader struct{}

func (Loader) GetCurrentAuthProvider(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error) {
	config, err := loadByDefaultRules(explicitFilename)
	if err != nil {
		return nil, fmt.Errorf("could not load the kubeconfig: %w", err)
	}
	auth, err := findCurrentAuthProvider(config, contextName, userName)
	if err != nil {
		return nil, fmt.Errorf("could not find the current auth provider: %w", err)
	}
	return auth, nil
}

func loadByDefaultRules(explicitFilename string) (*api.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = explicitFilename
	config, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("load error: %w", err)
	}
	return config, err
}

// findCurrentAuthProvider resolves the current auth provider.
// If contextName is given, this returns the user of the context.
// If userName is given, this ignores the context and returns the user.
// If any context or user is not found, this returns an error.
func findCurrentAuthProvider(config *api.Config, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error) {
	if userName == "" {
		if contextName == "" {
			contextName = kubeconfig.ContextName(config.CurrentContext)
		}
		contextNode, ok := config.Contexts[string(contextName)]
		if !ok {
			return nil, fmt.Errorf("context %s does not exist", contextName)
		}
		userName = kubeconfig.UserName(contextNode.AuthInfo)
	}
	userNode, ok := config.AuthInfos[string(userName)]
	if !ok {
		return nil, fmt.Errorf("user %s does not exist", userName)
	}
	if userNode.AuthProvider == nil {
		return nil, errors.New("auth-provider is missing")
	}
	if userNode.AuthProvider.Name != "oidc" {
		return nil, fmt.Errorf("auth-provider.name must be oidc but is %s", userNode.AuthProvider.Name)
	}
	if userNode.AuthProvider.Config == nil {
		return nil, errors.New("auth-provider.config is missing")
	}

	m := userNode.AuthProvider.Config
	var extraScopes []string
	if m["extra-scopes"] != "" {
		extraScopes = strings.Split(m["extra-scopes"], ",")
	}
	return &kubeconfig.AuthProvider{
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
