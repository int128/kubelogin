package authentication

import (
	"context"
	"fmt"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/devicecode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
)

// Set provides the use-case of Authentication.
var Set = wire.NewSet(
	wire.Struct(new(Authentication), "*"),
	wire.Bind(new(Interface), new(*Authentication)),
	wire.Struct(new(authcode.Browser), "*"),
	wire.Struct(new(authcode.Keyboard), "*"),
	wire.Struct(new(ropc.ROPC), "*"),
	wire.Struct(new(devicecode.DeviceCode), "*"),
)

type Interface interface {
	Do(ctx context.Context, in Input) (*Output, error)
}

// Input represents an input DTO of the Authentication use-case.
type Input struct {
	Provider        oidc.Provider
	GrantOptionSet  GrantOptionSet
	CachedTokenSet  *oidc.TokenSet // optional
	TLSClientConfig tlsclientconfig.Config
	ForceRefresh    bool
	UseAccessToken  bool
}

type GrantOptionSet struct {
	AuthCodeBrowserOption  *authcode.BrowserOption
	AuthCodeKeyboardOption *authcode.KeyboardOption
	ROPCOption             *ropc.Option
	DeviceCodeOption       *devicecode.Option
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
type Authentication struct {
	ClientFactory    client.FactoryInterface
	Logger           logger.Interface
	Clock            clock.Interface
	AuthCodeBrowser  *authcode.Browser
	AuthCodeKeyboard *authcode.Keyboard
	ROPC             *ropc.ROPC
	DeviceCode       *devicecode.DeviceCode
}

func (u *Authentication) Do(ctx context.Context, in Input) (*Output, error) {
	if in.CachedTokenSet != nil {
		if in.ForceRefresh {
			u.Logger.V(1).Infof("forcing refresh of the existing token")
		} else {
			u.Logger.V(1).Infof("checking expiration of the existing token")
			// Skip verification of the token to reduce time of a discovery request.
			// Here it trusts the signature and claims and checks only expiration,
			// because the token has been verified before caching.
			claims, err := in.CachedTokenSet.DecodeWithoutVerify()
			if err != nil {
				return nil, fmt.Errorf("invalid token cache (you may need to remove): %w", err)
			}
			if !claims.IsExpired(u.Clock) {
				u.Logger.V(1).Infof("you already have a valid token until %s", claims.Expiry)
				return &Output{
					AlreadyHasValidIDToken: true,
					TokenSet:               *in.CachedTokenSet,
				}, nil
			}
			u.Logger.V(1).Infof("you have an expired token at %s", claims.Expiry)
		}
	}

	u.Logger.V(1).Infof("initializing an OpenID Connect client")
	oidcClient, err := u.ClientFactory.New(ctx, in.Provider, in.TLSClientConfig, in.UseAccessToken)
	if err != nil {
		return nil, fmt.Errorf("oidc error: %w", err)
	}

	if in.CachedTokenSet != nil && in.CachedTokenSet.RefreshToken != "" {
		u.Logger.V(1).Infof("refreshing the token")
		tokenSet, err := oidcClient.Refresh(ctx, in.CachedTokenSet.RefreshToken)
		if err == nil {
			return &Output{TokenSet: *tokenSet}, nil
		}
		u.Logger.V(1).Infof("could not refresh the token: %s", err)
	}

	if in.GrantOptionSet.AuthCodeBrowserOption != nil {
		tokenSet, err := u.AuthCodeBrowser.Do(ctx, in.GrantOptionSet.AuthCodeBrowserOption, oidcClient)
		if err != nil {
			return nil, fmt.Errorf("authcode-browser error: %w", err)
		}
		return &Output{TokenSet: *tokenSet}, nil
	}
	if in.GrantOptionSet.AuthCodeKeyboardOption != nil {
		tokenSet, err := u.AuthCodeKeyboard.Do(ctx, in.GrantOptionSet.AuthCodeKeyboardOption, oidcClient)
		if err != nil {
			return nil, fmt.Errorf("authcode-keyboard error: %w", err)
		}
		return &Output{TokenSet: *tokenSet}, nil
	}
	if in.GrantOptionSet.ROPCOption != nil {
		tokenSet, err := u.ROPC.Do(ctx, in.GrantOptionSet.ROPCOption, oidcClient)
		if err != nil {
			return nil, fmt.Errorf("ropc error: %w", err)
		}
		return &Output{TokenSet: *tokenSet}, nil
	}
	if in.GrantOptionSet.DeviceCodeOption != nil {
		tokenSet, err := u.DeviceCode.Do(ctx, in.GrantOptionSet.DeviceCodeOption, oidcClient)
		if err != nil {
			return nil, fmt.Errorf("device-code error: %w", err)
		}
		return &Output{TokenSet: *tokenSet}, nil
	}
	return nil, fmt.Errorf("any authorization grant must be set")
}
