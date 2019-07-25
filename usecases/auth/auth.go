package auth

import (
	"context"
	"time"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
	"golang.org/x/xerrors"
)

// Set provides the use-case of Authentication.
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

// Authentication provides the internal use-case of authentication.
//
// If the IDToken is not set, it performs the authentication flow.
// If the IDToken is valid, it does nothing.
// If the IDtoken has expired and the RefreshToken is set, it refreshes the token.
// If the RefreshToken has expired, it performs the authentication flow.
//
// The authentication flow is determined as:
//
// If the Username is not set, it performs the authorization code flow.
// Otherwise, it performs the resource owner password credentials flow.
// If the Password is not set, it asks a password by the prompt.
//
type Authentication struct {
	OIDC               adaptors.OIDC
	Env                adaptors.Env
	Logger             adaptors.Logger
	ShowLocalServerURL usecases.LoginShowLocalServerURL
}

func (u *Authentication) Do(ctx context.Context, in usecases.AuthenticationIn) (*usecases.AuthenticationOut, error) {
	client, err := u.OIDC.New(ctx, adaptors.OIDCClientConfig{
		Config:         in.OIDCConfig,
		CACertFilename: in.CACertFilename,
		SkipTLSVerify:  in.SkipTLSVerify,
	})
	if err != nil {
		return nil, xerrors.Errorf("could not create an OIDC client: %w", err)
	}

	if in.OIDCConfig.IDToken != "" {
		u.Logger.Debugf(1, "Verifying the existing token")
		out, err := client.Verify(ctx, adaptors.OIDCVerifyIn{IDToken: in.OIDCConfig.IDToken})
		if err != nil {
			return nil, xerrors.Errorf("you need to remove the existing token manually: %w", err)
		}
		if out.IDTokenExpiry.After(time.Now()) { //TODO: inject time service
			u.Logger.Debugf(1, "You already have a valid token")
			return &usecases.AuthenticationOut{
				AlreadyHasValidIDToken: true,
				IDToken:                in.OIDCConfig.IDToken,
				RefreshToken:           in.OIDCConfig.RefreshToken,
				IDTokenExpiry:          out.IDTokenExpiry,
				IDTokenClaims:          out.IDTokenClaims,
			}, nil
		}
		u.Logger.Debugf(1, "You have an expired token at %s", out.IDTokenExpiry)
	}

	if in.OIDCConfig.RefreshToken != "" {
		u.Logger.Debugf(1, "Refreshing the token")
		out, err := client.Refresh(ctx, adaptors.OIDCRefreshIn{
			RefreshToken: in.OIDCConfig.RefreshToken,
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
