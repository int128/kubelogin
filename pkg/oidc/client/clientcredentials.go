package client

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type clientCredentialsInterface interface {
	GetTokenByClientCredentials(ctx context.Context, in GetTokenByClientCredentialsInput) (*oidc.TokenSet, error)
}

type GetTokenByClientCredentialsInput struct {
	EndpointParams map[string][]string
}

// GetTokenByClientCredentials performs the client credentials flow.
func (c *client) GetTokenByClientCredentials(ctx context.Context, in GetTokenByClientCredentialsInput) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	c.logger.V(1).Infof("%s, %s, %v", c.oauth2Config.ClientID, c.oauth2Config.Endpoint.AuthURL, c.oauth2Config.Scopes)

	config := clientcredentials.Config{
		ClientID:       c.oauth2Config.ClientID,
		ClientSecret:   c.oauth2Config.ClientSecret,
		TokenURL:       c.oauth2Config.Endpoint.TokenURL,
		Scopes:         c.oauth2Config.Scopes,
		EndpointParams: in.EndpointParams,
		AuthStyle:      oauth2.AuthStyleInHeader,
	}
	source := config.TokenSource(ctx)
	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("could not acquire token: %w", err)
	}
	if c.useAccessToken {
		return &oidc.TokenSet{
			IDToken:      token.AccessToken,
			RefreshToken: token.RefreshToken,
		}, nil
	}
	return c.verifyToken(ctx, token, "")
}
