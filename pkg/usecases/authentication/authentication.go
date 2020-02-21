package authentication

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/clock"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/domain/jwt"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_authentication/mock_authentication.go github.com/int128/kubelogin/pkg/usecases/authentication Interface

// Set provides the use-case of Authentication.
var Set = wire.NewSet(
	wire.Struct(new(Authentication), "*"),
	wire.Bind(new(Interface), new(*Authentication)),
	wire.Struct(new(AuthCode), "*"),
	wire.Struct(new(AuthCodeKeyboard), "*"),
	wire.Struct(new(ROPC), "*"),
)

type Interface interface {
	Do(ctx context.Context, in Input) (*Output, error)
}

// Input represents an input DTO of the Authentication use-case.
type Input struct {
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	ExtraScopes    []string // optional
	CertPool       certpool.Interface
	SkipTLSVerify  bool
	IDToken        string // optional
	RefreshToken   string // optional
	GrantOptionSet GrantOptionSet
}

type GrantOptionSet struct {
	AuthCodeOption         *AuthCodeOption
	AuthCodeKeyboardOption *AuthCodeKeyboardOption
	ROPCOption             *ROPCOption
}

type AuthCodeOption struct {
	SkipOpenBrowser bool
	BindAddress     []string
}

type AuthCodeKeyboardOption struct{}

type ROPCOption struct {
	Username string
	Password string // If empty, read a password using Reader.ReadPassword()
}

// Output represents an output DTO of the Authentication use-case.
type Output struct {
	AlreadyHasValidIDToken bool
	IDToken                string
	IDTokenClaims          jwt.Claims
	RefreshToken           string
}

const usernamePrompt = "Username: "
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
	NewOIDCClient    oidcclient.NewFunc
	Logger           logger.Interface
	Clock            clock.Interface
	AuthCode         *AuthCode
	AuthCodeKeyboard *AuthCodeKeyboard
	ROPC             *ROPC
}

func (u *Authentication) Do(ctx context.Context, in Input) (*Output, error) {
	if in.IDToken != "" {
		u.Logger.V(1).Infof("checking expiration of the existing token")
		// Skip verification of the token to reduce time of a discovery request.
		// Here it trusts the signature and claims and checks only expiration,
		// because the token has been verified before caching.
		claims, err := jwt.DecodeWithoutVerify(in.IDToken)
		if err != nil {
			return nil, xerrors.Errorf("invalid token and you need to remove the cache: %w", err)
		}
		if !claims.IsExpired(u.Clock) {
			u.Logger.V(1).Infof("you already have a valid token until %s", claims.Expiry)
			return &Output{
				AlreadyHasValidIDToken: true,
				IDToken:                in.IDToken,
				RefreshToken:           in.RefreshToken,
				IDTokenClaims:          *claims,
			}, nil
		}
		u.Logger.V(1).Infof("you have an expired token at %s", claims.Expiry)
	}

	u.Logger.V(1).Infof("initializing an OpenID Connect client")
	client, err := u.NewOIDCClient(ctx, oidcclient.Config{
		IssuerURL:     in.IssuerURL,
		ClientID:      in.ClientID,
		ClientSecret:  in.ClientSecret,
		ExtraScopes:   in.ExtraScopes,
		CertPool:      in.CertPool,
		SkipTLSVerify: in.SkipTLSVerify,
		Logger:        u.Logger,
	})
	if err != nil {
		return nil, xerrors.Errorf("could not initialize the OpenID Connect client: %w", err)
	}

	if in.RefreshToken != "" {
		u.Logger.V(1).Infof("refreshing the token")
		out, err := client.Refresh(ctx, in.RefreshToken)
		if err == nil {
			return &Output{
				IDToken:       out.IDToken,
				IDTokenClaims: out.IDTokenClaims,
				RefreshToken:  out.RefreshToken,
			}, nil
		}
		u.Logger.V(1).Infof("could not refresh the token: %s", err)
	}

	if in.GrantOptionSet.AuthCodeOption != nil {
		return u.AuthCode.Do(ctx, in.GrantOptionSet.AuthCodeOption, client)
	}
	if in.GrantOptionSet.AuthCodeKeyboardOption != nil {
		return u.AuthCodeKeyboard.Do(ctx, in.GrantOptionSet.AuthCodeKeyboardOption, client)
	}
	if in.GrantOptionSet.ROPCOption != nil {
		return u.ROPC.Do(ctx, in.GrantOptionSet.ROPCOption, client)
	}
	return nil, xerrors.Errorf("any authorization grant must be set")
}
