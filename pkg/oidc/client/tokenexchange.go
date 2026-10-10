package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/int128/kubelogin/pkg/oidc"
	"golang.org/x/oauth2"
)

const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
const AccessTokenType = "urn:ietf:params:oauth:token-type:access_token"

type GetTokenByTokenExchangeInput struct {
	Resource           []string
	Audience           []string
	RequestedTokenType string
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string

	AuthRequestExtraParams map[string]string
}

func (c *client) GetTokenByTokenExchange(ctx context.Context, in GetTokenByTokenExchangeInput) (*oidc.TokenSet, error) {
	ctx = c.wrapContext(ctx)
	c.logger.V(1).Infof(
		"Token Exchange Request: ClientID=%s, AuthURL=%s, Scopes=%v, Audience=%v, Resource=%v",
		c.oauth2Config.ClientID,
		c.oauth2Config.Endpoint.AuthURL,
		c.oauth2Config.Scopes,
		in.Audience,
		in.Resource,
	)

	addParamIfNotEmpty := func(opts []oauth2.AuthCodeOption, key, value string) []oauth2.AuthCodeOption {
		if value != "" {
			return append(opts, oauth2.SetAuthURLParam(key, value))
		}
		return opts
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("grant_type", TokenExchangeGrantType),
		oauth2.SetAuthURLParam("subject_token", in.SubjectToken),
		oauth2.SetAuthURLParam("subject_token_type", in.SubjectTokenType),
	}

	for _, res := range in.Resource {
		if res != "" {
			opts = append(opts, oauth2.SetAuthURLParam("resource", res))
		}
	}

	for _, aud := range in.Audience {
		if aud != "" {
			opts = append(opts, oauth2.SetAuthURLParam("audience", aud))
		}
	}
	opts = addParamIfNotEmpty(opts, "requested_token_type", in.RequestedTokenType)
	opts = addParamIfNotEmpty(opts, "actor_token", in.ActorToken)
	opts = addParamIfNotEmpty(opts, "actor_token_type", in.ActorTokenType)

	if len(c.oauth2Config.Scopes) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("scope", strings.Join(c.oauth2Config.Scopes, " ")))
	}

	for param, val := range in.AuthRequestExtraParams {
		opts = append(opts, oauth2.SetAuthURLParam(param, val))
	}

	token, err := c.oauth2Config.Exchange(ctx, "", opts...)
	if err != nil {
		return nil, fmt.Errorf("could not acquire token: %w", err)
	}

	return c.verifyToken(ctx, token, "")
}
