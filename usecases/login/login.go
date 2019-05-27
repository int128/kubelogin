package login

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/pkg/errors"
)

const oidcConfigErrorMessage = `No OIDC configuration found. Did you setup kubectl for OIDC authentication?
  kubectl config set-credentials CONTEXT_NAME \
    --auth-provider oidc \
    --auth-provider-arg idp-issuer-url=https://issuer.example.com \
    --auth-provider-arg client-id=YOUR_CLIENT_ID \
    --auth-provider-arg client-secret=YOUR_CLIENT_SECRET`

type Login struct {
	KubeConfig adaptors.KubeConfig
	OIDC       adaptors.OIDC
	Logger     adaptors.Logger
	Prompt     usecases.LoginPrompt
}

func (u *Login) Do(ctx context.Context, in usecases.LoginIn) error {
	u.Logger.Debugf(1, "WARNING: log may contain your secrets such as token or password")

	mergedKubeConfig, err := u.KubeConfig.LoadByDefaultRules(in.KubeConfigFilename)
	if err != nil {
		return errors.Wrapf(err, "could not load the kubeconfig")
	}
	auth, err := kubeconfig.FindCurrentAuth(mergedKubeConfig, in.KubeContextName, in.KubeUserName)
	if err != nil {
		u.Logger.Printf(oidcConfigErrorMessage)
		return errors.Wrapf(err, "could not find the current authentication provider")
	}
	u.Logger.Debugf(1, "Using the authentication provider of the user %s", auth.UserName)
	destinationKubeConfigFilename := auth.User.LocationOfOrigin
	if destinationKubeConfigFilename == "" {
		return errors.Errorf("could not determine the kubeconfig to write")
	}
	u.Logger.Debugf(1, "A token will be written to %s", destinationKubeConfigFilename)

	oidcClient, err := u.OIDC.NewClient(adaptors.HTTPClientConfig{
		OIDCConfig:                   auth.OIDCConfig,
		CertificateAuthorityFilename: in.CertificateAuthorityFilename,
		SkipTLSVerify:                in.SkipTLSVerify,
	})
	if err != nil {
		return errors.Wrapf(err, "could not create an OIDC client")
	}

	if auth.OIDCConfig.IDToken() != "" {
		u.Logger.Debugf(1, "Found the ID token in the kubeconfig")
		token, err := oidcClient.Verify(ctx, adaptors.OIDCVerifyIn{Config: auth.OIDCConfig})
		if err == nil {
			u.Logger.Printf("You already have a valid token until %s", token.Expiry)
			u.dumpIDToken(token)
			return nil
		}
		u.Logger.Debugf(1, "The ID token was invalid: %s", err)
	}

	out, err := u.authenticate(ctx, oidcClient, auth, in)
	if err != nil {
		return errors.Wrapf(err, "could not get a token from the OIDC provider")
	}
	u.Logger.Printf("You got a valid token until %s", out.VerifiedIDToken.Expiry)
	u.dumpIDToken(out.VerifiedIDToken)

	if err := u.writeToken(destinationKubeConfigFilename, auth.UserName, out); err != nil {
		return errors.Wrapf(err, "could not write the token to the kubeconfig")
	}
	return nil
}

func (u *Login) authenticate(ctx context.Context, client adaptors.OIDCClient, auth *kubeconfig.CurrentAuth, in usecases.LoginIn) (*adaptors.OIDCAuthenticateOut, error) {
	if in.Username != "" {
		return client.AuthenticateByPassword(ctx, adaptors.OIDCAuthenticateByPasswordIn{
			Config:   auth.OIDCConfig,
			Username: in.Username,
			Password: in.Password,
		})
	}
	return client.AuthenticateByCode(ctx,
		adaptors.OIDCAuthenticateByCodeIn{
			Config:          auth.OIDCConfig,
			LocalServerPort: in.ListenPort,
			SkipOpenBrowser: in.SkipOpenBrowser,
			Prompt:          u.Prompt,
		})
}

func (u *Login) dumpIDToken(token *oidc.IDToken) {
	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		u.Logger.Debugf(1, "Error while inspection of the ID token: %s", err)
	}
	for k, v := range claims {
		u.Logger.Debugf(1, "The ID token has the claim: %s=%v", k, v)
	}
}

func (u *Login) writeToken(filename string, userName kubeconfig.UserName, out *adaptors.OIDCAuthenticateOut) error {
	config, err := u.KubeConfig.LoadFromFile(filename)
	if err != nil {
		return errors.Wrapf(err, "could not load %s", filename)
	}
	auth, err := kubeconfig.FindCurrentAuth(config, "", userName)
	if err != nil {
		return errors.Wrapf(err, "could not find the user %s in %s", userName, filename)
	}
	auth.OIDCConfig.SetIDToken(out.IDToken)
	auth.OIDCConfig.SetRefreshToken(out.RefreshToken)
	u.Logger.Debugf(1, "Writing the ID token and refresh token to %s", filename)
	if err := u.KubeConfig.WriteToFile(config, filename); err != nil {
		return errors.Wrapf(err, "could not update %s", filename)
	}
	u.Logger.Printf("Updated %s", filename)
	return nil
}

type Prompt struct {
	Logger adaptors.Logger
}

func (p *Prompt) ShowLocalServerURL(url string) {
	p.Logger.Printf("Open %s for authentication", url)
}
