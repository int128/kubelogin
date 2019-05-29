package login

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
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

	auth, err := u.KubeConfig.GetCurrentAuth(in.KubeConfigFilename, in.KubeContextName, in.KubeUserName)
	if err != nil {
		u.Logger.Printf(oidcConfigErrorMessage)
		return errors.Wrapf(err, "could not find the current authentication provider")
	}
	u.Logger.Debugf(1, "Using the authentication provider of the user %s", auth.UserName)
	u.Logger.Debugf(1, "A token will be written to %s", auth.LocationOfOrigin)

	client, err := u.OIDC.New(adaptors.OIDCClientConfig{
		Config:         auth.OIDCConfig,
		CACertFilename: in.CACertFilename,
		SkipTLSVerify:  in.SkipTLSVerify,
	})
	if err != nil {
		return errors.Wrapf(err, "could not create an OIDC client")
	}

	if auth.OIDCConfig.IDToken != "" {
		u.Logger.Debugf(1, "Found the ID token in the kubeconfig")
		token, err := client.Verify(ctx, adaptors.OIDCVerifyIn{Config: auth.OIDCConfig})
		if err == nil {
			u.Logger.Printf("You already have a valid token until %s", token.Expiry)
			u.dumpIDToken(token)
			return nil
		}
		u.Logger.Debugf(1, "The ID token was invalid: %s", err)
	}

	out, err := u.authenticate(ctx, client, auth, in)
	if err != nil {
		return errors.Wrapf(err, "could not get a token from the OIDC provider")
	}
	u.Logger.Printf("You got a valid token until %s", out.VerifiedIDToken.Expiry)
	u.dumpIDToken(out.VerifiedIDToken)

	auth.OIDCConfig.IDToken = out.IDToken
	auth.OIDCConfig.RefreshToken = out.RefreshToken
	u.Logger.Debugf(1, "Writing the ID token and refresh token to %s", auth.LocationOfOrigin)
	if err := u.KubeConfig.UpdateAuth(auth); err != nil {
		return errors.Wrapf(err, "could not write the token to the kubeconfig")
	}
	return nil
}

func (u *Login) authenticate(ctx context.Context, client adaptors.OIDCClient, auth *kubeconfig.Auth, in usecases.LoginIn) (*adaptors.OIDCAuthenticateOut, error) {
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

type Prompt struct {
	Logger adaptors.Logger
}

func (p *Prompt) ShowLocalServerURL(url string) {
	p.Logger.Printf("Open %s for authentication", url)
}
