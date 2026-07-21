package tokenexchange

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
)

type TokenExchangeOption struct {
	Resource           []string
	Audience           []string
	RequestedTokenType string
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string

	AuthRequestExtraParams map[string]string
}

// TokenExchage provides the oauth2 token exchange flow.
type TokenExchange struct {
	Logger logger.Interface
}

func (u *TokenExchange) Do(ctx context.Context, in *TokenExchangeOption, oidcClient client.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the oauth2 toke exchange flow")
	if in == nil {
		return nil, fmt.Errorf("nil input")
	}

	if in.SubjectToken == "" {
		return nil, fmt.Errorf("subject_token is required")
	}

	if in.SubjectTokenType == "" {
		return nil, fmt.Errorf("subject_token_type is required")
	}

	if in.ActorToken != "" && in.ActorTokenType == "" {
		return nil, fmt.Errorf("actor_token_type is required when actor_token is set")
	}
	if in.ActorToken == "" && in.ActorTokenType != "" {
		return nil, fmt.Errorf("actor_token_type may not be set when actor_token is not set")
	}

	tokenSet, err := oidcClient.GetTokenByTokenExchange(ctx, client.GetTokenByTokenExchangeInput{
		Resource:           in.Resource,
		Audience:           in.Audience,
		RequestedTokenType: in.RequestedTokenType,
		SubjectToken:       in.SubjectToken,
		SubjectTokenType:   in.SubjectTokenType,
		ActorToken:         in.ActorToken,
		ActorTokenType:     in.ActorTokenType,

		AuthRequestExtraParams: in.AuthRequestExtraParams,
	})
	if err != nil {
		return nil, fmt.Errorf("could not exchange the token: %w", err)
	}

	u.Logger.V(1).Infof("finished the oauth2 token exchange flow")
	return tokenSet, nil
}
