package auth

import (
	"context"
	"time"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
	"golang.org/x/xerrors"
)

// Set provides the use-cases of logging in.
var Set = wire.NewSet(
	wire.Struct(new(Authentication), "*"),
	wire.Bind(new(usecases.Authentication), new(*Authentication)),
)

// ExtraSet is a set of interaction components for e2e testing.
var ExtraSet = wire.NewSet(
	wire.Struct(new(ShowLocalServerURL), "*"),
	wire.Bind(new(usecases.LoginShowLocalServerURL), new(*ShowLocalServerURL)),
)

const passwordPrompt = "Password: "

type Authentication struct {
	OIDC               adaptors.OIDC
	Env                adaptors.Env
	Logger             adaptors.Logger
	ShowLocalServerURL usecases.LoginShowLocalServerURL
}

func (u *Authentication) Do(ctx context.Context, in usecases.AuthenticationIn) (*usecases.AuthenticationOut, error) {
	client, err := u.OIDC.New(ctx, adaptors.OIDCClientConfig{
		Config:         in.CurrentAuth.OIDCConfig,
		CACertFilename: in.CACertFilename,
		SkipTLSVerify:  in.SkipTLSVerify,
	})
	if err != nil {
		return nil, xerrors.Errorf("could not create an OIDC client: %w", err)
	}

	if in.CurrentAuth.OIDCConfig.IDToken != "" {
		u.Logger.Debugf(1, "Verifying the token in the kubeconfig")
		out, err := client.Verify(ctx, adaptors.OIDCVerifyIn{IDToken: in.CurrentAuth.OIDCConfig.IDToken})
		if err != nil {
			return nil, xerrors.Errorf("invalid ID token in the kubeconfig, you need to remove it manually: %w", err)
		}
		if out.IDTokenExpiry.After(time.Now()) { //TODO: inject time service
			u.Logger.Debugf(1, "You already have a valid token in the kubeconfig")
			return &usecases.AuthenticationOut{
				AlreadyHasValidIDToken: true,
				IDToken:                in.CurrentAuth.OIDCConfig.IDToken,
				RefreshToken:           in.CurrentAuth.OIDCConfig.RefreshToken,
				IDTokenExpiry:          out.IDTokenExpiry,
				IDTokenClaims:          out.IDTokenClaims,
			}, nil
		}
		u.Logger.Debugf(1, "You have an expired token at %s", out.IDTokenExpiry)
	}

	if in.CurrentAuth.OIDCConfig.RefreshToken != "" {
		u.Logger.Debugf(1, "Refreshing the token")
		out, err := client.Refresh(ctx, adaptors.OIDCRefreshIn{
			RefreshToken: in.CurrentAuth.OIDCConfig.RefreshToken,
		})
		if err == nil {
			return &usecases.AuthenticationOut{
				IDToken:       out.IDToken,
				RefreshToken:  out.RefreshToken,
				IDTokenExpiry: out.IDTokenExpiry,
				IDTokenClaims: out.IDTokenClaims,
			}, nil
		}
		u.Logger.Debugf(1, "Could not refresh the token: %s", err)
	}

	if in.Username == "" {
		u.Logger.Debugf(1, "Performing the authentication code flow")
		out, err := client.AuthenticateByCode(ctx, adaptors.OIDCAuthenticateByCodeIn{
			LocalServerPort:    in.ListenPort,
			SkipOpenBrowser:    in.SkipOpenBrowser,
			ShowLocalServerURL: u.ShowLocalServerURL,
		})
		if err != nil {
			return nil, xerrors.Errorf("error while the authorization code flow: %w", err)
		}
		return &usecases.AuthenticationOut{
			IDToken:       out.IDToken,
			RefreshToken:  out.RefreshToken,
			IDTokenExpiry: out.IDTokenExpiry,
			IDTokenClaims: out.IDTokenClaims,
		}, nil
	}

	u.Logger.Debugf(1, "Performing the resource owner password credentials flow")
	if in.Password == "" {
		in.Password, err = u.Env.ReadPassword(passwordPrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not read a password: %w", err)
		}
	}
	out, err := client.AuthenticateByPassword(ctx, adaptors.OIDCAuthenticateByPasswordIn{
		Username: in.Username,
		Password: in.Password,
	})
	if err != nil {
		return nil, xerrors.Errorf("error while the resource owner password credentials flow: %w", err)
	}
	return &usecases.AuthenticationOut{
		IDToken:       out.IDToken,
		RefreshToken:  out.RefreshToken,
		IDTokenExpiry: out.IDTokenExpiry,
		IDTokenClaims: out.IDTokenClaims,
	}, nil
}

// ShowLocalServerURL just shows the URL of local server to console.
type ShowLocalServerURL struct {
	Logger adaptors.Logger
}

func (s *ShowLocalServerURL) ShowLocalServerURL(url string) {
	s.Logger.Printf("Open %s for authentication", url)
}
