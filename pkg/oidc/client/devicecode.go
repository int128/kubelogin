package client

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/pkce"
	"github.com/int128/oauth2dev"
	"golang.org/x/oauth2"
)

// GetDeviceAuthorization initializes the device authorization code challenge.
// If pkceParams has a method set, the PKCE code challenge is included in the request.
func (c *client) GetDeviceAuthorization(ctx context.Context, pkceParams pkce.Params) (*oauth2dev.AuthorizationResponse, error) {
	ctx = c.wrapContext(ctx)
	if pkceParams.Method == pkce.NoMethod {
		config := c.oauth2Config
		config.Endpoint = oauth2.Endpoint{
			AuthURL: c.provider.Endpoint().DeviceAuthURL,
		}
		return oauth2dev.RetrieveCode(ctx, config)
	}
	// Use the stdlib DeviceAuth which supports AuthCodeOptions (e.g. PKCE challenge).
	// c.oauth2Config already has Endpoint.DeviceAuthURL set from the factory.
	da, err := c.oauth2Config.DeviceAuth(ctx, pkceParams.AuthCodeOption())
	if err != nil {
		return nil, err
	}
	return &oauth2dev.AuthorizationResponse{
		DeviceCode:              da.DeviceCode,
		UserCode:                da.UserCode,
		VerificationURI:         da.VerificationURI,
		VerificationURIComplete: da.VerificationURIComplete,
		Interval:                int(da.Interval),
	}, nil
}

// ExchangeDeviceCode exchanges the device authorization code for an oidc.TokenSet.
// If pkceParams has a method set, the PKCE code verifier is included in the token request.
func (c *client) ExchangeDeviceCode(ctx context.Context, authResponse *oauth2dev.AuthorizationResponse, pkceParams pkce.Params) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	var (
		token *oauth2.Token
		err   error
	)
	if pkceParams.Method == pkce.NoMethod {
		token, err = oauth2dev.PollToken(ctx, c.oauth2Config, *authResponse)
	} else {
		da := &oauth2.DeviceAuthResponse{
			DeviceCode:              authResponse.DeviceCode,
			UserCode:                authResponse.UserCode,
			VerificationURI:         authResponse.VerificationURI,
			VerificationURIComplete: authResponse.VerificationURIComplete,
			Interval:                int64(authResponse.Interval),
		}
		token, err = c.oauth2Config.DeviceAccessToken(ctx, da, pkceParams.TokenRequestOption())
	}
	if err != nil {
		return nil, fmt.Errorf("device-code: exchange failed: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}
