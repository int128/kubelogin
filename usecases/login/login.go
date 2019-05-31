package login

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
	"github.com/pkg/errors"
)

const oidcConfigErrorMessage = `No OIDC configuration found. Did you setup kubectl for OIDC authentication?
  kubectl config set-credentials CONTEXT_NAME \
    --auth-provider oidc \
    --auth-provider-arg idp-issuer-url=https://issuer.example.com \
    --auth-provider-arg client-id=YOUR_CLIENT_ID \
    --auth-provider-arg client-secret=YOUR_CLIENT_SECRET`

const passwordPrompt = "Password: "

type Login struct {
	Kubeconfig         adaptors.Kubeconfig
	OIDC               adaptors.OIDC
	Env                adaptors.Env
	Logger             adaptors.Logger
	ShowLocalServerURL usecases.LoginShowLocalServerURL
}

func (u *Login) Do(ctx context.Context, in usecases.LoginIn) error {
	u.Logger.Debugf(1, "WARNING: log may contain your secrets such as token or password")

	auth, err := u.Kubeconfig.GetCurrentAuth(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
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
			dumpIDToken(u.Logger, token)
			return nil
		}
		u.Logger.Debugf(1, "The ID token was invalid: %s", err)
	}

	var tokenSet *adaptors.OIDCAuthenticateOut
	if in.Username != "" {
		if in.Password == "" {
			in.Password, err = u.Env.ReadPassword(passwordPrompt)
			if err != nil {
				return errors.Wrapf(err, "could not read a password")
			}
		}
		out, err := client.AuthenticateByPassword(ctx, adaptors.OIDCAuthenticateByPasswordIn{
			Config:   auth.OIDCConfig,
			Username: in.Username,
			Password: in.Password,
		})
		if err != nil {
			return errors.Wrapf(err, "error while the resource owner password credentials grant flow")
		}
		tokenSet = out
	} else {
		out, err := client.AuthenticateByCode(ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          auth.OIDCConfig,
			LocalServerPort: in.ListenPort,
			SkipOpenBrowser: in.SkipOpenBrowser,
			Prompt:          u.ShowLocalServerURL,
		})
		if err != nil {
			return errors.Wrapf(err, "error while the authorization code grant flow")
		}
		tokenSet = out
	}
	u.Logger.Printf("You got a valid token until %s", tokenSet.VerifiedIDToken.Expiry)
	dumpIDToken(u.Logger, tokenSet.VerifiedIDToken)
	auth.OIDCConfig.IDToken = tokenSet.IDToken
	auth.OIDCConfig.RefreshToken = tokenSet.RefreshToken

	u.Logger.Debugf(1, "Writing the ID token and refresh token to %s", auth.LocationOfOrigin)
	if err := u.Kubeconfig.UpdateAuth(auth); err != nil {
		return errors.Wrapf(err, "could not write the token to the kubeconfig")
	}
	return nil
}

func dumpIDToken(logger adaptors.Logger, token *oidc.IDToken) {
	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		logger.Debugf(1, "Error while inspection of the ID token: %s", err)
	}
	for k, v := range claims {
		logger.Debugf(1, "The ID token has the claim: %s=%v", k, v)
	}
}

type ShowLocalServerURL struct {
	Logger adaptors.Logger
}

func (s *ShowLocalServerURL) ShowLocalServerURL(url string) {
	s.Logger.Printf("Open %s for authentication", url)
}
