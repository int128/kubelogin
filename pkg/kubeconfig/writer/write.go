package writer

import (
	"fmt"
	"strings"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/kubeconfig"
	"k8s.io/client-go/tools/clientcmd"
)

var Set = wire.NewSet(
	wire.Struct(new(Writer), "*"),
	wire.Bind(new(Interface), new(*Writer)),
)

type Interface interface {
	UpdateAuthProvider(p kubeconfig.AuthProvider) error
}

type Writer struct{}

func (Writer) UpdateAuthProvider(p kubeconfig.AuthProvider) error {
	config, err := clientcmd.LoadFromFile(p.LocationOfOrigin)
	if err != nil {
		return fmt.Errorf("could not load %s: %w", p.LocationOfOrigin, err)
	}
	userNode, ok := config.AuthInfos[string(p.UserName)]
	if !ok {
		return fmt.Errorf("user %s does not exist", p.UserName)
	}
	if userNode.AuthProvider == nil {
		return fmt.Errorf("auth-provider is missing")
	}
	if userNode.AuthProvider.Name != "oidc" {
		return fmt.Errorf("auth-provider must be oidc but is %s", userNode.AuthProvider.Name)
	}
	copyAuthProviderConfig(p, userNode.AuthProvider.Config)
	if err := clientcmd.WriteToFile(*config, p.LocationOfOrigin); err != nil {
		return fmt.Errorf("could not update %s: %w", p.LocationOfOrigin, err)
	}
	return nil
}

func copyAuthProviderConfig(p kubeconfig.AuthProvider, m map[string]string) {
	setOrDeleteKey(m, "idp-issuer-url", p.IDPIssuerURL)
	setOrDeleteKey(m, "client-id", p.ClientID)
	setOrDeleteKey(m, "client-secret", p.ClientSecret)
	setOrDeleteKey(m, "idp-certificate-authority", p.IDPCertificateAuthority)
	setOrDeleteKey(m, "idp-certificate-authority-data", p.IDPCertificateAuthorityData)
	extraScopes := strings.Join(p.ExtraScopes, ",")
	setOrDeleteKey(m, "extra-scopes", extraScopes)
	setOrDeleteKey(m, "id-token", p.IDToken)
	setOrDeleteKey(m, "refresh-token", p.RefreshToken)
}

func setOrDeleteKey(m map[string]string, key, value string) {
	if value == "" {
		delete(m, key)
		return
	}
	m[key] = value
}
