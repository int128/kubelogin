package usecases

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/pkg/errors"
	"go.uber.org/dig"
)

const oidcConfigErrorMessage = `No OIDC configuration found. Did you setup kubectl for OIDC authentication?
  kubectl config set-credentials %[1]s \
    --auth-provider oidc \
    --auth-provider-arg idp-issuer-url=https://issuer.example.com \
    --auth-provider-arg client-id=YOUR_CLIENT_ID \
    --auth-provider-arg client-secret=YOUR_CLIENT_SECRET`

func NewLogin(i Login) usecases.Login {
	return &i
}

type Login struct {
	dig.In
	KubeConfig adaptors.KubeConfig
	HTTP       adaptors.HTTP
	OIDC       adaptors.OIDC
	Logger     adaptors.Logger
}

func (u *Login) Do(ctx context.Context, in usecases.LoginIn) error {
	cfg, err := u.KubeConfig.LoadFromFile(in.KubeConfig)
	if err != nil {
		return errors.Wrapf(err, "could not read the kubeconfig")
	}

	u.Logger.Logf("Using current-context: %s", cfg.CurrentContext)
	authProvider, err := kubeconfig.FindOIDCAuthProvider(cfg)
	if err != nil {
		u.Logger.Logf(oidcConfigErrorMessage, cfg.CurrentContext)
		return errors.Wrapf(err, "could not find an oidc auth-provider in the kubeconfig")
	}

	clientConfig := u.HTTP.NewClientConfig()
	clientConfig.SetSkipTLSVerify(in.SkipTLSVerify)
	if authProvider.IDPCertificateAuthority() != "" {
		filename := authProvider.IDPCertificateAuthority()
		u.Logger.Logf("Using the certificate %s", filename)
		if err := clientConfig.AddCertificateFromFile(filename); err != nil {
			u.Logger.Logf("Skip the certificate %s: %s", filename, err)
		}
	}
	if authProvider.IDPCertificateAuthorityData() != "" {
		encoded := authProvider.IDPCertificateAuthorityData()
		u.Logger.Logf("Using certificate of idp-certificate-authority-data")
		if err := clientConfig.AddEncodedCertificate(encoded); err != nil {
			u.Logger.Logf("Skip the certificate of idp-certificate-authority-data: %s", err)
		}
	}
	hc, err := u.HTTP.NewClient(clientConfig)
	if err != nil {
		return errors.Wrapf(err, "could not create a HTTP client")
	}

	if token := u.verifyIDToken(ctx, adaptors.OIDCVerifyTokenIn{
		IDToken:  authProvider.IDToken(),
		Issuer:   authProvider.IDPIssuerURL(),
		ClientID: authProvider.ClientID(),
		Client:   hc,
	}); token != nil {
		u.Logger.Logf("You already have a valid token (until %s)", token.Expiry)
		return nil
	}

	out, err := u.OIDC.Authenticate(ctx, adaptors.OIDCAuthenticateIn{
		Issuer:          authProvider.IDPIssuerURL(),
		ClientID:        authProvider.ClientID(),
		ClientSecret:    authProvider.ClientSecret(),
		ExtraScopes:     authProvider.ExtraScopes(),
		Client:          hc,
		LocalServerPort: in.ListenPort,
		SkipOpenBrowser: in.SkipOpenBrowser,
	})
	if err != nil {
		return errors.Wrapf(err, "could not get token from OIDC provider")
	}

	u.Logger.Logf("Got a token for subject=%s", out.VerifiedIDToken.Subject)
	authProvider.SetIDToken(out.IDToken)
	authProvider.SetRefreshToken(out.RefreshToken)
	if err := u.KubeConfig.WriteToFile(cfg, in.KubeConfig); err != nil {
		return errors.Wrapf(err, "could not update the kubeconfig")
	}
	u.Logger.Logf("Updated %s", in.KubeConfig)
	return nil
}

func (u *Login) verifyIDToken(ctx context.Context, in adaptors.OIDCVerifyTokenIn) *oidc.IDToken {
	if in.IDToken == "" {
		return nil
	}
	token, err := u.OIDC.VerifyIDToken(ctx, in)
	if err != nil {
		//TODO: u.Logger.Debugf("Current ID token is invalid: %s", err)
		return nil
	}
	return token
}
