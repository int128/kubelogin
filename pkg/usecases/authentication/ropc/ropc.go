package ropc

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/reader"
	"github.com/int128/kubelogin/pkg/oidc"
	"golang.org/x/xerrors"
)

const usernamePrompt = "Username: "
const passwordPrompt = "Password: "

type Option struct {
	// require omitempty for tokencache.Key
	Username string `json:",omitempty"`
	Password string `json:",omitempty"` // If empty, read a password using Reader.ReadPassword()
}

// ROPC provides the resource owner password credentials flow.
type ROPC struct {
	Reader reader.Interface
	Logger logger.Interface
}

func (u *ROPC) Do(ctx context.Context, in *Option, client oidcclient.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the resource owner password credentials flow")
	if in.Username == "" {
		var err error
		in.Username, err = u.Reader.ReadString(usernamePrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not read a username: %w", err)
		}
	}
	if in.Password == "" {
		var err error
		in.Password, err = u.Reader.ReadPassword(passwordPrompt)
		if err != nil {
			return nil, xerrors.Errorf("could not read a password: %w", err)
		}
	}
	tokenSet, err := client.GetTokenByROPC(ctx, in.Username, in.Password)
	if err != nil {
		return nil, xerrors.Errorf("resource owner password credentials flow error: %w", err)
	}
	u.Logger.V(1).Infof("finished the resource owner password credentials flow")
	return tokenSet, nil
}
