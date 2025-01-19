package ropc

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/infrastructure/reader"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
)

const usernamePrompt = "Username: "
const passwordPrompt = "Password: "

type Option struct {
	Username string
	Password string // If empty, read a password using Reader.ReadPassword()
}

// ROPC provides the resource owner password credentials flow.
type ROPC struct {
	Reader reader.Interface
	Logger logger.Interface
}

func (u *ROPC) Do(ctx context.Context, in *Option, oidcClient client.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the resource owner password credentials flow")
	if in.Username == "" {
		var err error
		in.Username, err = u.Reader.ReadString(usernamePrompt)
		if err != nil {
			return nil, fmt.Errorf("could not read a username: %w", err)
		}
	}
	if in.Password == "" {
		var err error
		in.Password, err = u.Reader.ReadPassword(passwordPrompt)
		if err != nil {
			return nil, fmt.Errorf("could not read a password: %w", err)
		}
	}
	tokenSet, err := oidcClient.GetTokenByROPC(ctx, in.Username, in.Password)
	if err != nil {
		return nil, fmt.Errorf("resource owner password credentials flow error: %w", err)
	}
	u.Logger.V(1).Infof("finished the resource owner password credentials flow")
	return tokenSet, nil
}
