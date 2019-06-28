package login

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
	"golang.org/x/xerrors"
)

// Set provides the use-cases of logging in.
var Set = wire.NewSet(
	wire.Struct(new(Login), "*"),
	wire.Struct(new(Exec), "*"),
	wire.Bind(new(usecases.Login), new(*Login)),
	wire.Bind(new(usecases.LoginAndExec), new(*Exec)),
)

const oidcConfigErrorMessage = `No OIDC configuration found. Did you setup kubectl for OIDC authentication?
  kubectl config set-credentials CONTEXT_NAME \
    --auth-provider oidc \
    --auth-provider-arg idp-issuer-url=https://issuer.example.com \
    --auth-provider-arg client-id=YOUR_CLIENT_ID \
    --auth-provider-arg client-secret=YOUR_CLIENT_SECRET`

// Login provides the use case of login to the provider.
// If the current auth provider is not oidc, show the error.
// If the kubeconfig has a valid token, do nothing.
// Otherwise, update the kubeconfig.
type Login struct {
	Authentication usecases.Authentication
	Kubeconfig     adaptors.Kubeconfig
	Logger         adaptors.Logger
}

func (u *Login) Do(ctx context.Context, in usecases.LoginIn) error {
	u.Logger.Debugf(1, "WARNING: log may contain your secrets such as token or password")

	auth, err := u.Kubeconfig.GetCurrentAuth(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
	if err != nil {
		u.Logger.Printf(oidcConfigErrorMessage)
		return xerrors.Errorf("could not find the current authentication provider: %w", err)
	}
	u.Logger.Debugf(1, "Using the authentication provider of the user %s", auth.UserName)
	u.Logger.Debugf(1, "A token will be written to %s", auth.LocationOfOrigin)

	out, err := u.Authentication.Do(ctx, usecases.AuthenticationIn{
		CurrentAuth:     auth,
		SkipOpenBrowser: in.SkipOpenBrowser,
		ListenPort:      in.ListenPort,
		Username:        in.Username,
		Password:        in.Password,
		CACertFilename:  in.CACertFilename,
		SkipTLSVerify:   in.SkipTLSVerify,
	})
	if err != nil {
		return xerrors.Errorf("error while authentication: %w", err)
	}
	for k, v := range out.IDTokenClaims {
		u.Logger.Debugf(1, "ID token has the claim: %s=%v", k, v)
	}
	if out.AlreadyHasValidIDToken {
		u.Logger.Printf("You already have a valid token until %s", out.IDTokenExpiry)
		return nil
	}

	u.Logger.Printf("You got a valid token until %s", out.IDTokenExpiry)
	auth.OIDCConfig.IDToken = out.IDToken
	auth.OIDCConfig.RefreshToken = out.RefreshToken
	u.Logger.Debugf(1, "Writing the ID token and refresh token to %s", auth.LocationOfOrigin)
	if err := u.Kubeconfig.UpdateAuth(auth); err != nil {
		return xerrors.Errorf("could not write the token to the kubeconfig: %w", err)
	}
	return nil
}
