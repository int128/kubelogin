package login

import (
	"context"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
	"github.com/pkg/errors"
)

// Exec provide the use case of wrapping the kubectl command.
// If the current auth provider is not oidc, just run kubectl.
// If the kubeconfig has a valid token, just run kubectl.
// Otherwise, update the kubeconfig and run kubectl.
type Exec struct {
	Kubeconfig         adaptors.Kubeconfig
	OIDC               adaptors.OIDC
	Env                adaptors.Env
	Logger             adaptors.Logger
	ShowLocalServerURL usecases.LoginShowLocalServerURL
}

func (u *Exec) Do(ctx context.Context, in usecases.LoginAndExecIn) (*usecases.LoginAndExecOut, error) {
	if err := u.doInternal(ctx, in.LoginIn); err != nil {
		return nil, errors.WithStack(err)
	}
	exitCode, err := u.Env.Exec(ctx, in.Executable, in.Args)
	if err != nil {
		return nil, errors.Wrapf(err, "could not execute kubectl")
	}
	return &usecases.LoginAndExecOut{ExitCode: exitCode}, nil
}

func (u *Exec) doInternal(ctx context.Context, in usecases.LoginIn) error {
	u.Logger.Debugf(1, "WARNING: log may contain your secrets such as token or password")

	auth, err := u.Kubeconfig.GetCurrentAuth(in.KubeconfigFilename, in.KubeconfigContext, in.KubeconfigUser)
	if err != nil {
		u.Logger.Debugf(1, "The current authentication provider is not oidc: %s", err)
		return nil
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
			u.Logger.Debugf(1, "You already have a valid token until %s", token.Expiry)
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
			Config:             auth.OIDCConfig,
			LocalServerPort:    in.ListenPort,
			SkipOpenBrowser:    in.SkipOpenBrowser,
			ShowLocalServerURL: u.ShowLocalServerURL,
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
