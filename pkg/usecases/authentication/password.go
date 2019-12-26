package authentication

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"golang.org/x/xerrors"
)

// ROPC provides the resource owner password credentials flow.
type ROPC struct {
	Env    env.Interface
	Logger logger.Interface
}

func (u *ROPC) Do(ctx context.Context, in *ROPCOption, client oidcclient.Interface) (*Output, error) {
	u.Logger.V(1).Infof("performing the resource owner password credentials flow")
	if in.Username == "" {
		var err error
		in.Username, err = u.Env.ReadString(usernamePrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not get the username: %w", err)
		}
	}
	if in.Password == "" {
		var err error
		in.Password, err = u.Env.ReadPassword(passwordPrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not read a password: %w", err)
		}
	}
	tokenSet, err := client.GetTokenByROPC(ctx, in.Username, in.Password)
	if err != nil {
		return nil, xerrors.Errorf("error while the resource owner password credentials flow: %w", err)
	}
	return &Output{
		IDToken:       tokenSet.IDToken,
		IDTokenClaims: tokenSet.IDTokenClaims,
		RefreshToken:  tokenSet.RefreshToken,
	}, nil
}
