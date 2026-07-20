package client

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/oidc"
	"golang.org/x/oauth2"
)

type GetTokenByTokenExchangeInput struct {
}

func (c *client) GetTokenByTokenExchange(ctx context.Context, in GetTokenByTokenExchangeInput) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	c.logger.V(1).Infof("")

	// TODO(vdbe): implement this
	token, err := &oauth2.Token{}, fmt.Errorf("`GetTokenByTokenExchange` not yet implemented")
	if err != nil {
		return nil, fmt.Errorf("could not acquire token: %w", err)
	}

	return c.verifyToken(ctx, token, "")
}
