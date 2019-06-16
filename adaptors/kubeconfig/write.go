package kubeconfig

import (
	"strings"

	"github.com/int128/kubelogin/models/kubeconfig"
	"golang.org/x/xerrors"
	"k8s.io/client-go/tools/clientcmd"
)

func (*Kubeconfig) UpdateAuth(auth *kubeconfig.Auth) error {
	config, err := clientcmd.LoadFromFile(auth.LocationOfOrigin)
	if err != nil {
		return xerrors.Errorf("could not load %s: %w", auth.LocationOfOrigin, err)
	}
	userNode, ok := config.AuthInfos[string(auth.UserName)]
	if !ok {
		return xerrors.Errorf("user %s does not exist", auth.UserName)
	}
	if userNode.AuthProvider == nil {
		return xerrors.Errorf("auth-provider is missing")
	}
	if userNode.AuthProvider.Name != "oidc" {
		return xerrors.Errorf("auth-provider must be oidc but is %s", userNode.AuthProvider.Name)
	}
	copyOIDCConfig(auth.OIDCConfig, userNode.AuthProvider.Config)
	if err := clientcmd.WriteToFile(*config, auth.LocationOfOrigin); err != nil {
		return xerrors.Errorf("could not update %s: %w", auth.LocationOfOrigin, err)
	}
	return nil
}

func copyOIDCConfig(config kubeconfig.OIDCConfig, m map[string]string) {
	setOrDeleteKey(m, "idp-issuer-url", config.IDPIssuerURL)
	setOrDeleteKey(m, "client-id", config.ClientID)
	setOrDeleteKey(m, "client-secret", config.ClientSecret)
	setOrDeleteKey(m, "idp-certificate-authority", config.IDPCertificateAuthority)
	setOrDeleteKey(m, "idp-certificate-authority-data", config.IDPCertificateAuthorityData)
	extraScopes := strings.Join(config.ExtraScopes, ",")
	setOrDeleteKey(m, "extra-scopes", extraScopes)
	setOrDeleteKey(m, "id-token", config.IDToken)
	setOrDeleteKey(m, "refresh-token", config.RefreshToken)
}

func setOrDeleteKey(m map[string]string, key, value string) {
	if value == "" {
		delete(m, key)
		return
	}
	m[key] = value
}
