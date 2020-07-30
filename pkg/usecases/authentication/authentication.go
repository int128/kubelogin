package authentication

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/clock"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/jwt"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_authentication/mock_authentication.go github.com/int128/kubelogin/pkg/usecases/authentication Interface

// Set provides the use-case of Authentication.
var Set = wire.NewSet(
	wire.Struct(new(Authentication), "*"),
	wire.Bind(new(Interface), new(*Authentication)),
	wire.Struct(new(authcode.Browser), "*"),
	wire.Struct(new(authcode.Keyboard), "*"),
	wire.Struct(new(ropc.ROPC), "*"),
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
	AuthCodeBrowserOption  *authcode.BrowserOption
	AuthCodeKeyboardOption *authcode.KeyboardOption
	ROPCOption             *ropc.Option
}

// Output represents an output DTO of the Authentication use-case.
type Output struct {
	AlreadyHasValidIDToken bool
	TokenSet               oidc.TokenSet
}

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
	AuthCodeBrowser  *authcode.Browser
	AuthCodeKeyboard *authcode.Keyboard
	ROPC             *ropc.ROPC
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
				TokenSet: oidc.TokenSet{
					IDToken:       in.IDToken,
					RefreshToken:  in.RefreshToken,
					IDTokenClaims: *claims,
				},
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
				TokenSet: oidc.TokenSet{
					IDToken:       out.IDToken,
					IDTokenClaims: out.IDTokenClaims,
					RefreshToken:  out.RefreshToken,
				},
			}, nil
		}
		u.Logger.V(1).Infof("could not refresh the token: %s", err)
	}

	if in.GrantOptionSet.AuthCodeBrowserOption != nil {
		tokenSet, err := u.AuthCodeBrowser.Do(ctx, in.GrantOptionSet.AuthCodeBrowserOption, client)
		if err != nil {
			return nil, xerrors.Errorf("authcode-browser error: %w", err)
		}
		return &Output{TokenSet: *tokenSet}, nil
	}
	if in.GrantOptionSet.AuthCodeKeyboardOption != nil {
		tokenSet, err := u.AuthCodeKeyboard.Do(ctx, in.GrantOptionSet.AuthCodeKeyboardOption, client)
		if err != nil {
			return nil, xerrors.Errorf("authcode-keyboard error: %w", err)
		}
		return &Output{TokenSet: *tokenSet}, nil
	}
	if in.GrantOptionSet.ROPCOption != nil {
		tokenSet, err := u.ROPC.Do(ctx, in.GrantOptionSet.ROPCOption, client)
		if err != nil {
			return nil, xerrors.Errorf("ropc error: %w", err)
		}
		return &Output{TokenSet: *tokenSet}, nil
	}
	return nil, xerrors.Errorf("any authorization grant must be set")
}
