package login

import (
	"context"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
	"golang.org/x/xerrors"
)

// Exec provide the use case of transparently executing kubectl.
//
// If the current auth provider is not oidc, just run kubectl.
// If the kubeconfig has a valid token, just run kubectl.
// Otherwise, update the kubeconfig and run kubectl.
//
type Exec struct {
	Authentication usecases.Authentication
	Kubeconfig     adaptors.Kubeconfig
	Env            adaptors.Env
	Logger         adaptors.Logger
}

func (u *Exec) Do(ctx context.Context, in usecases.LoginAndExecIn) (*usecases.LoginAndExecOut, error) {
	if err := u.login(ctx, in.LoginIn); err != nil {
		return nil, xerrors.Errorf("could not log in to the provider: %w", err)
	}
	u.Logger.Debugf(1, "Executing the command %s %s", in.Executable, in.Args)
	exitCode, err := u.Env.Exec(ctx, in.Executable, in.Args)
	if err != nil {
		return nil, xerrors.Errorf("could not execute kubectl: %w", err)
	}
	u.Logger.Debugf(1, "The command exited with status %d", exitCode)
	return &usecases.LoginAndExecOut{ExitCode: exitCode}, nil
}

func (u *Exec) login(ctx context.Context, in usecases.LoginIn) error {
	u.Logger.Debugf(1, "WARNING: log may contain your secrets such as token or password")

	authProvider, err := u.Kubeconfig.GetCurrentAuthProvider(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
	if err != nil {
		u.Logger.Debugf(1, "The current authentication provider is not oidc: %s", err)
		return nil
	}
	u.Logger.Debugf(1, "Using the authentication provider of the user %s", authProvider.UserName)
	u.Logger.Debugf(1, "A token will be written to %s", authProvider.LocationOfOrigin)

	out, err := u.Authentication.Do(ctx, usecases.AuthenticationIn{
		CurrentAuthProvider: authProvider,
		SkipOpenBrowser:     in.SkipOpenBrowser,
		ListenPort:          in.ListenPort,
		Username:            in.Username,
		Password:            in.Password,
		CACertFilename:      in.CACertFilename,
		SkipTLSVerify:       in.SkipTLSVerify,
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
	authProvider.OIDCConfig.IDToken = out.IDToken
	authProvider.OIDCConfig.RefreshToken = out.RefreshToken

	u.Logger.Debugf(1, "Writing the ID token and refresh token to %s", authProvider.LocationOfOrigin)
	if err := u.Kubeconfig.UpdateAuthProvider(authProvider); err != nil {
		return xerrors.Errorf("could not write the token to the kubeconfig: %w", err)
	}
	return nil
}
