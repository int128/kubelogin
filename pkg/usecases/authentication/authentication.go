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
	wire.Struct(new(AuthCodeBrowser), "*"),
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
	IDToken        string // optional, from the token cache
	RefreshToken   string // optional, from the token cache
	GrantOptionSet GrantOptionSet
}

type GrantOptionSet struct {
	AuthCodeBrowserOption  *AuthCodeBrowserOption
	AuthCodeKeyboardOption *AuthCodeKeyboardOption
	ROPCOption             *ROPCOption
}

type AuthCodeBrowserOption struct {
	SkipOpenBrowser        bool
	BindAddress            []string
	RedirectURLHostname    string
	AuthRequestExtraParams map[string]string
}

type AuthCodeKeyboardOption struct {
	AuthRequestExtraParams map[string]string
}

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
	OIDCClient       oidcclient.FactoryInterface
	Logger           logger.Interface
	Clock            clock.Interface
	AuthCodeBrowser  *AuthCodeBrowser
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
			return nil, xerrors.Errorf("invalid token cache (you may need to remove): %w", err)
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
	client, err := u.OIDCClient.New(ctx, oidcclient.Config{
		IssuerURL:     in.IssuerURL,
		ClientID:      in.ClientID,
		ClientSecret:  in.ClientSecret,
		ExtraScopes:   in.ExtraScopes,
		CertPool:      in.CertPool,
		SkipTLSVerify: in.SkipTLSVerify,
	})
	if err != nil {
		return nil, xerrors.Errorf("oidc error: %w", err)
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

	if in.GrantOptionSet.AuthCodeBrowserOption != nil {
		return u.AuthCodeBrowser.Do(ctx, in.GrantOptionSet.AuthCodeBrowserOption, client)
	}
	if in.GrantOptionSet.AuthCodeKeyboardOption != nil {
		return u.AuthCodeKeyboard.Do(ctx, in.GrantOptionSet.AuthCodeKeyboardOption, client)
	}
	if in.GrantOptionSet.ROPCOption != nil {
		return u.ROPC.Do(ctx, in.GrantOptionSet.ROPCOption, client)
	}
	return nil, xerrors.Errorf("any authorization grant must be set")
}
