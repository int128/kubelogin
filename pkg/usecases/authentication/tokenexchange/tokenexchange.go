package tokenexchange

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
)

type TokenExchangeOption struct {
}

// TokenExchage provides the oauth2 token exchange flow.
type TokenExchange struct {
	Logger logger.Interface
}

func (u *TokenExchange) Do(ctx context.Context, in *TokenExchangeOption, oidcClient client.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the oauth2 toke exchange code flow")
	if in == nil {
		return nil, fmt.Errorf("nil input")
	}

	// TODO(vdbe): implement this
	tokenSet, err := &oidc.TokenSet{}, fmt.Errorf("tokenexchange tokenset not yet implemented")
	if err != nil {
		return nil, fmt.Errorf("could not exchange the token: %w", err)
	}

	u.Logger.V(1).Infof("finished the oauth2 toke exchange code flow")
	return tokenSet, nil
}
