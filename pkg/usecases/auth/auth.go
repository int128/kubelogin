package auth

import (
	"context"
	"time"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidc"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_auth/mock_auth.go github.com/int128/kubelogin/pkg/usecases/auth Interface

// Set provides the use-case of Authentication.
var Set = wire.NewSet(
	wire.Struct(new(Authentication), "*"),
	wire.Bind(new(Interface), new(*Authentication)),
)

// ExtraSet is a set of interaction components for e2e testing.
var ExtraSet = wire.NewSet(
	wire.Struct(new(ShowLocalServerURL), "*"),
	wire.Bind(new(ShowLocalServerURLInterface), new(*ShowLocalServerURL)),
)

type Interface interface {
	Do(ctx context.Context, in Input) (*Output, error)
}

// ShowLocalServerURLInterface provides an interface to notify the URL of local server.
// It is needed for the end-to-end tests.
type ShowLocalServerURLInterface interface {
	ShowLocalServerURL(url string)
}

// Input represents an input DTO of the Authentication use-case.
type Input struct {
	OIDCConfig      kubeconfig.OIDCConfig
	SkipOpenBrowser bool
	ListenPort      []int
	Username        string // If set, perform the resource owner password credentials grant
	Password        string // If empty, read a password using Env.ReadPassword()
	CACertFilename  string // If set, use the CA cert
	SkipTLSVerify   bool
}

// Output represents an output DTO of the Authentication use-case.
type Output struct {
	AlreadyHasValidIDToken bool
	IDTokenExpiry          time.Time
	IDTokenClaims          map[string]string
	IDToken                string
	RefreshToken           string
}

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
	OIDCFactory        oidc.FactoryInterface
	OIDCDecoder        oidc.DecoderInterface
	Env                env.Interface
	Logger             logger.Interface
	ShowLocalServerURL ShowLocalServerURLInterface
}

func (u *Authentication) Do(ctx context.Context, in Input) (*Output, error) {
	if in.OIDCConfig.IDToken != "" {
		u.Logger.V(1).Infof("checking expiration of the existing token")
		// Skip verification of the token to reduce time of a discovery request.
		// Here it trusts the signature and claims and checks only expiration,
		// because the token has been verified before caching.
		token, err := u.OIDCDecoder.DecodeIDToken(in.OIDCConfig.IDToken)
		if err != nil {
			return nil, xerrors.Errorf("invalid token and you need to remove the cache: %w", err)
		}
		if token.IDTokenExpiry.After(time.Now()) { //TODO: inject time service
			u.Logger.V(1).Infof("you already have a valid token until %s", token.IDTokenExpiry)
			return &Output{
				AlreadyHasValidIDToken: true,
				IDToken:                in.OIDCConfig.IDToken,
				RefreshToken:           in.OIDCConfig.RefreshToken,
				IDTokenExpiry:          token.IDTokenExpiry,
				IDTokenClaims:          token.IDTokenClaims,
			}, nil
		}
		u.Logger.V(1).Infof("you have an expired token at %s", token.IDTokenExpiry)
	}

	u.Logger.V(1).Infof("initializing an OIDCFactory client")
	client, err := u.OIDCFactory.New(ctx, oidc.ClientConfig{
		Config:         in.OIDCConfig,
		CACertFilename: in.CACertFilename,
		SkipTLSVerify:  in.SkipTLSVerify,
	})
	if err != nil {
		return nil, xerrors.Errorf("could not create an OIDCFactory client: %w", err)
	}

	if in.OIDCConfig.RefreshToken != "" {
		u.Logger.V(1).Infof("refreshing the token")
		out, err := client.Refresh(ctx, oidc.RefreshIn{
			RefreshToken: in.OIDCConfig.RefreshToken,
		})
		if err == nil {
			return &Output{
				IDToken:       out.IDToken,
				RefreshToken:  out.RefreshToken,
				IDTokenExpiry: out.IDTokenExpiry,
				IDTokenClaims: out.IDTokenClaims,
			}, nil
		}
		u.Logger.V(1).Infof("could not refresh the token: %s", err)
	}

	if in.Username == "" {
		u.Logger.V(1).Infof("performing the authentication code flow")
		out, err := client.AuthenticateByCode(ctx, oidc.AuthenticateByCodeIn{
			LocalServerPort:    in.ListenPort,
			SkipOpenBrowser:    in.SkipOpenBrowser,
			ShowLocalServerURL: u.ShowLocalServerURL,
		})
		if err != nil {
			return nil, xerrors.Errorf("error while the authorization code flow: %w", err)
		}
		return &Output{
			IDToken:       out.IDToken,
			RefreshToken:  out.RefreshToken,
			IDTokenExpiry: out.IDTokenExpiry,
			IDTokenClaims: out.IDTokenClaims,
		}, nil
	}

	u.Logger.V(1).Infof("performing the resource owner password credentials flow")
	if in.Password == "" {
		in.Password, err = u.Env.ReadPassword(passwordPrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not read a password: %w", err)
		}
	}
	out, err := client.AuthenticateByPassword(ctx, oidc.AuthenticateByPasswordIn{
		Username: in.Username,
		Password: in.Password,
	})
	if err != nil {
		return nil, xerrors.Errorf("error while the resource owner password credentials flow: %w", err)
	}
	return &Output{
		IDToken:       out.IDToken,
		RefreshToken:  out.RefreshToken,
		IDTokenExpiry: out.IDTokenExpiry,
		IDTokenClaims: out.IDTokenClaims,
	}, nil
}

// ShowLocalServerURL just shows the URL of local server to console.
type ShowLocalServerURL struct {
	Logger logger.Interface
}

func (s *ShowLocalServerURL) ShowLocalServerURL(url string) {
	s.Logger.Printf("Open %s for authentication", url)
}
