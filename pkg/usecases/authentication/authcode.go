package authentication

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

// AuthCode provides the authentication code flow.
type AuthCode struct {
	Env                  env.Interface
	Logger               logger.Interface
	LocalServerReadyFunc LocalServerReadyFunc // only for e2e tests
}

func (u *AuthCode) Do(ctx context.Context, in *AuthCodeOption, client oidcclient.Interface) (*Output, error) {
	u.Logger.V(1).Infof("performing the authentication code flow")
	readyChan := make(chan string, 1)
	defer close(readyChan)
	var out Output
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		select {
		case url, ok := <-readyChan:
			if !ok {
				return nil
			}
			u.Logger.Printf("Open %s for authentication", url)
			if u.LocalServerReadyFunc != nil {
				u.LocalServerReadyFunc(url)
			}
			if in.SkipOpenBrowser {
				return nil
			}
			if err := u.Env.OpenBrowser(url); err != nil {
				u.Logger.V(1).Infof("could not open the browser: %s", err)
			}
			return nil
		case <-ctx.Done():
			return xerrors.Errorf("context cancelled while waiting for the local server: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		tokenSet, err := client.AuthenticateByCode(ctx, in.BindAddress, readyChan)
		if err != nil {
			return xerrors.Errorf("error while the authorization code flow: %w", err)
		}
		out = Output{
			IDToken:        tokenSet.IDToken,
			RefreshToken:   tokenSet.RefreshToken,
			IDTokenSubject: tokenSet.IDTokenSubject,
			IDTokenExpiry:  tokenSet.IDTokenExpiry,
			IDTokenClaims:  tokenSet.IDTokenClaims,
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, xerrors.Errorf("error while the authorization code flow: %w", err)
	}
	return &out, nil
}
