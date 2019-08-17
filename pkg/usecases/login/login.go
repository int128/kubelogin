package login

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors"
	"github.com/int128/kubelogin/pkg/usecases"
	"golang.org/x/xerrors"
)

// Set provides the use-cases of logging in.
var Set = wire.NewSet(
	wire.Struct(new(Login), "*"),
	wire.Bind(new(usecases.Login), new(*Login)),
)

const oidcConfigErrorMessage = `No OIDC configuration found. Did you setup kubectl for OIDC authentication?
  kubectl config set-credentials CONTEXT_NAME \
    --auth-provider oidc \
    --auth-provider-arg idp-issuer-url=https://issuer.example.com \
    --auth-provider-arg client-id=YOUR_CLIENT_ID \
    --auth-provider-arg client-secret=YOUR_CLIENT_SECRET`

// Login provides the use case of explicit login.
//
// If the current auth provider is not oidc, show the error.
// If the kubeconfig has a valid token, do nothing.
// Otherwise, update the kubeconfig.
//
type Login struct {
	Authentication usecases.Authentication
	Kubeconfig     adaptors.Kubeconfig
	Logger         adaptors.Logger
}

func (u *Login) Do(ctx context.Context, in usecases.LoginIn) error {
	u.Logger.Debugf(1, "WARNING: log may contain your secrets such as token or password")

	authProvider, err := u.Kubeconfig.GetCurrentAuthProvider(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
	if err != nil {
		u.Logger.Printf(oidcConfigErrorMessage)
		return xerrors.Errorf("could not find the current authentication provider: %w", err)
	}
	u.Logger.Debugf(1, "using the authentication provider of the user %s", authProvider.UserName)
	u.Logger.Debugf(1, "a token will be written to %s", authProvider.LocationOfOrigin)

	out, err := u.Authentication.Do(ctx, usecases.AuthenticationIn{
		OIDCConfig:      authProvider.OIDCConfig,
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
		u.Logger.Debugf(1, "the ID token has the claim: %s=%v", k, v)
	}
	if out.AlreadyHasValidIDToken {
		u.Logger.Printf("You already have a valid token until %s", out.IDTokenExpiry)
		return nil
	}

	u.Logger.Printf("You got a valid token until %s", out.IDTokenExpiry)
	authProvider.OIDCConfig.IDToken = out.IDToken
	authProvider.OIDCConfig.RefreshToken = out.RefreshToken
	u.Logger.Debugf(1, "writing the ID token and refresh token to %s", authProvider.LocationOfOrigin)
	if err := u.Kubeconfig.UpdateAuthProvider(authProvider); err != nil {
		return xerrors.Errorf("could not write the token to the kubeconfig: %w", err)
	}
	return nil
}
