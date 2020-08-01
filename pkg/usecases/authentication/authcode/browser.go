package authcode

import (
	"context"

	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/pkce"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

type BrowserOption struct {
	SkipOpenBrowser        bool
	BindAddress            []string
	OpenURLAfterAuthentication string
	RedirectURLHostname    string
	AuthRequestExtraParams map[string]string
}

// Browser provides the authentication code flow using the browser.
type Browser struct {
	Browser browser.Interface
	Logger  logger.Interface
}

func (u *Browser) Do(ctx context.Context, o *BrowserOption, client oidcclient.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the authentication code flow using the browser")
	state, err := oidc.NewState()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a state: %w", err)
	}
	nonce, err := oidc.NewNonce()
	if err != nil {
		return nil, xerrors.Errorf("could not generate a nonce: %w", err)
	}
	p, err := pkce.New(client.SupportedPKCEMethods())
	if err != nil {
		return nil, xerrors.Errorf("could not generate PKCE parameters: %w", err)
	}
	successHTML := BrowserSuccessHTML
	if o.OpenURLAfterAuthentication != "" {
		successHTML = BrowserRedirectHTML(o.OpenURLAfterAuthentication)
	}
	in := oidcclient.GetTokenByAuthCodeInput{
		BindAddress:            o.BindAddress,
		State:                  state,
		Nonce:                  nonce,
		PKCEParams:             p,
		RedirectURLHostname:    o.RedirectURLHostname,
		AuthRequestExtraParams: o.AuthRequestExtraParams,
		LocalServerSuccessHTML: successHTML,
	}
	readyChan := make(chan string, 1)
	defer close(readyChan)
	var out *oidc.TokenSet
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		select {
		case url, ok := <-readyChan:
			if !ok {
				return nil
			}
			if o.SkipOpenBrowser {
				u.Logger.Printf("Please visit the following URL in your browser: %s", url)
				return nil
			}
			u.Logger.V(1).Infof("opening %s in the browser", url)
			if err := u.Browser.Open(url); err != nil {
				u.Logger.Printf(`error: could not open the browser: %s

Please visit the following URL in your browser manually: %s`, err, url)
				return nil
			}
			return nil
		case <-ctx.Done():
			return xerrors.Errorf("context cancelled while waiting for the local server: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		tokenSet, err := client.GetTokenByAuthCode(ctx, in, readyChan)
		if err != nil {
			return xerrors.Errorf("authorization code flow error: %w", err)
		}
		out = tokenSet
		u.Logger.V(1).Infof("got a token set by the authorization code flow")
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, xerrors.Errorf("authentication error: %w", err)
	}
	u.Logger.V(1).Infof("finished the authorization code flow via the browser")
	return out, nil
}
