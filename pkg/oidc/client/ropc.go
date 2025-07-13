package client

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/oidc"
)

// GetTokenByROPC performs the resource owner password credentials flow.
func (c *client) GetTokenByROPC(ctx context.Context, username, password string) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	token, err := c.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("resource owner password credentials flow error: %w", err)
	}
	return c.verifyToken(ctx, token, "")
}
