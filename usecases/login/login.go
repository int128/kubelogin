package login

import (
	"context"

	"github.com/coreos/go-oidc"
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

// ExtraSet is a set of interaction components for e2e testing.
var ExtraSet = wire.NewSet(
	wire.Struct(new(ShowLocalServerURL), "*"),
	wire.Bind(new(usecases.LoginShowLocalServerURL), new(*ShowLocalServerURL)),
)

const oidcConfigErrorMessage = `No OIDC configuration found. Did you setup kubectl for OIDC authentication?
  kubectl config set-credentials CONTEXT_NAME \
    --auth-provider oidc \
    --auth-provider-arg idp-issuer-url=https://issuer.example.com \
    --auth-provider-arg client-id=YOUR_CLIENT_ID \
    --auth-provider-arg client-secret=YOUR_CLIENT_SECRET`

const passwordPrompt = "Password: "

// Login provides the use case of login to the provider.
// If the current auth provider is not oidc, show the error.
// If the kubeconfig has a valid token, do nothing.
// Otherwise, update the kubeconfig.
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
		return xerrors.Errorf("could not find the current authentication provider: %w", err)
	}
	u.Logger.Debugf(1, "Using the authentication provider of the user %s", auth.UserName)
	u.Logger.Debugf(1, "A token will be written to %s", auth.LocationOfOrigin)

	client, err := u.OIDC.New(ctx, adaptors.OIDCClientConfig{
		Config:         auth.OIDCConfig,
		CACertFilename: in.CACertFilename,
		SkipTLSVerify:  in.SkipTLSVerify,
	})
	if err != nil {
		return xerrors.Errorf("could not create an OIDC client: %w", err)
	}

	if auth.OIDCConfig.IDToken != "" {
		u.Logger.Debugf(1, "Found the ID token in the kubeconfig")
		token, err := client.Verify(ctx, adaptors.OIDCVerifyIn{IDToken: auth.OIDCConfig.IDToken})
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
				return xerrors.Errorf("could not read a password: %w", err)
			}
		}
		out, err := client.AuthenticateByPassword(ctx, adaptors.OIDCAuthenticateByPasswordIn{
			Username: in.Username,
			Password: in.Password,
		})
		if err != nil {
			return xerrors.Errorf("error while the resource owner password credentials grant flow: %w", err)
		}
		tokenSet = out
	} else {
		out, err := client.AuthenticateByCode(ctx, adaptors.OIDCAuthenticateByCodeIn{
			LocalServerPort:    in.ListenPort,
			SkipOpenBrowser:    in.SkipOpenBrowser,
			ShowLocalServerURL: u.ShowLocalServerURL,
		})
		if err != nil {
			return xerrors.Errorf("error while the authorization code grant flow: %w", err)
		}
		tokenSet = out
	}
	u.Logger.Printf("You got a valid token until %s", tokenSet.VerifiedIDToken.Expiry)
	dumpIDToken(u.Logger, tokenSet.VerifiedIDToken)
	auth.OIDCConfig.IDToken = tokenSet.IDToken
	auth.OIDCConfig.RefreshToken = tokenSet.RefreshToken

	u.Logger.Debugf(1, "Writing the ID token and refresh token to %s", auth.LocationOfOrigin)
	if err := u.Kubeconfig.UpdateAuth(auth); err != nil {
		return xerrors.Errorf("could not write the token to the kubeconfig: %w", err)
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

// ShowLocalServerURL just shows the URL of local server to console.
type ShowLocalServerURL struct {
	Logger adaptors.Logger
}

func (s *ShowLocalServerURL) ShowLocalServerURL(url string) {
	s.Logger.Printf("Open %s for authentication", url)
}
