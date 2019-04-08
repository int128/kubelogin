package usecases

import (
	"context"
	"log"
	"net/http"

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/pkg/errors"
)

type Login struct {
	KubeConfig adaptors.KubeConfig
	OIDC       adaptors.OIDC
}

func (u *Login) Do(ctx context.Context, in usecases.LoginIn) error {
	cfg, err := u.KubeConfig.LoadFromFile(in.KubeConfig)
	if err != nil {
		return errors.Wrapf(err, "could not read kubeconfig")
	}
	log.Printf("Using current-context: %s", cfg.CurrentContext)
	authProvider, err := kubeconfig.FindOIDCAuthProvider(cfg)
	if err != nil {
		return errors.Wrapf(err, `could not find OIDC configuration in kubeconfig,
			did you setup kubectl for OIDC authentication?
				kubectl config set-credentials %s \
					--auth-provider oidc \
					--auth-provider-arg idp-issuer-url=https://issuer.example.com \
					--auth-provider-arg client-id=YOUR_CLIENT_ID \
					--auth-provider-arg client-secret=YOUR_CLIENT_SECRET`,
			cfg.CurrentContext)
	}
	tlsConfig := tlsConfig(authProvider, in.SkipTLSVerify)
	token, err := u.OIDC.Authenticate(ctx, adaptors.OIDCAuthenticateIn{
		Issuer:          authProvider.IDPIssuerURL(),
		ClientID:        authProvider.ClientID(),
		ClientSecret:    authProvider.ClientSecret(),
		ExtraScopes:     authProvider.ExtraScopes(),
		Client:          &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		LocalServerPort: in.ListenPort,
		SkipOpenBrowser: in.SkipOpenBrowser,
	})
	if err != nil {
		return errors.Wrapf(err, "could not get token from OIDC provider")
	}

	authProvider.SetIDToken(token.IDToken)
	authProvider.SetRefreshToken(token.RefreshToken)
	if err := u.KubeConfig.WriteToFile(cfg, in.KubeConfig); err != nil {
		return errors.Wrapf(err, "could not update the kubeconfig")
	}
	log.Printf("Updated %s", in.KubeConfig)
	return nil
}
