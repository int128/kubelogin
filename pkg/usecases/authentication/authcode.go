package authentication

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/domain/oidc"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

// AuthCode provides the authentication code flow.
type AuthCode struct {
	Env     env.Interface
	Browser browser.Interface
	Logger  logger.Interface
}

func (u *AuthCode) Do(ctx context.Context, o *AuthCodeOption, client oidcclient.Interface) (*Output, error) {
	u.Logger.V(1).Infof("performing the authentication code flow")
	nonce, err := oidc.NewNonce()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a nonce: %w", err)
	}
	p, err := oidc.NewPKCEParams()
	if err != nil {
		return nil, xerrors.Errorf("could not generate PKCE parameters: %w", err)
	}
	in := oidcclient.GetTokenByAuthCodeInput{
		BindAddress:         o.BindAddress,
		Nonce:               nonce,
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
		CodeVerifier:        p.CodeVerifier,
	}
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
			if o.SkipOpenBrowser {
				return nil
			}
			if err := u.Browser.Open(url); err != nil {
				u.Logger.V(1).Infof("could not open the browser: %s", err)
			}
			return nil
		case <-ctx.Done():
			return xerrors.Errorf("context cancelled while waiting for the local server: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		tokenSet, err := client.GetTokenByAuthCode(ctx, in, readyChan)
		if err != nil {
			return xerrors.Errorf("error while the authorization code flow: %w", err)
		}
		out = Output{
			IDToken:       tokenSet.IDToken,
			IDTokenClaims: tokenSet.IDTokenClaims,
			RefreshToken:  tokenSet.RefreshToken,
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, xerrors.Errorf("error while the authorization code flow: %w", err)
	}
	return &out, nil
}
