package client

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/oauth2dev"
	"golang.org/x/oauth2"
)

// GetDeviceAuthorization initializes the device authorization code challenge
func (c *client) GetDeviceAuthorization(ctx context.Context) (*oauth2dev.AuthorizationResponse, error) {
	ctx = c.wrapContext(ctx)
	config := c.oauth2Config
	config.Endpoint = oauth2.Endpoint{
		AuthURL: c.deviceAuthorizationEndpoint,
	}
	return oauth2dev.RetrieveCode(ctx, config)
}

// ExchangeDeviceCode exchanges the device to an oidc.TokenSet
func (c *client) ExchangeDeviceCode(ctx context.Context, authResponse *oauth2dev.AuthorizationResponse) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	tokenResponse, err := oauth2dev.PollToken(ctx, c.oauth2Config, *authResponse)
	if err != nil {
		return nil, fmt.Errorf("device-code: exchange failed: %w", err)
	}
	return c.verifyToken(ctx, tokenResponse, "")
}
