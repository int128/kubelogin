package kubeconfig

import (
	"strings"

	"golang.org/x/xerrors"
	"k8s.io/client-go/tools/clientcmd"
)

func (*Kubeconfig) UpdateAuthProvider(p *AuthProvider) error {
	config, err := clientcmd.LoadFromFile(p.LocationOfOrigin)
	if err != nil {
		return xerrors.Errorf("could not load %s: %w", p.LocationOfOrigin, err)
	}
	userNode, ok := config.AuthInfos[string(p.UserName)]
	if !ok {
		return xerrors.Errorf("user %s does not exist", p.UserName)
	}
	if userNode.AuthProvider == nil {
		return xerrors.Errorf("auth-provider is missing")
	}
	if userNode.AuthProvider.Name != "oidc" {
		return xerrors.Errorf("auth-provider must be oidc but is %s", userNode.AuthProvider.Name)
	}
	copyAuthProviderConfig(p, userNode.AuthProvider.Config)
	if err := clientcmd.WriteToFile(*config, p.LocationOfOrigin); err != nil {
		return xerrors.Errorf("could not update %s: %w", p.LocationOfOrigin, err)
	}
	return nil
}

func copyAuthProviderConfig(p *AuthProvider, m map[string]string) {
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
