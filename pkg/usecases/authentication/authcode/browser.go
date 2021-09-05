package authcode

import (
	"context"
	"fmt"
	"time"

	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/pkce"
	"golang.org/x/sync/errgroup"
)

type BrowserOption struct {
	SkipOpenBrowser            bool
	BrowserCommand             string
	BindAddress                []string
	AuthenticationTimeout      time.Duration
	OpenURLAfterAuthentication string
	RedirectURLHostname        string
	AuthRequestExtraParams     map[string]string
	LocalServerCertFile        string
	LocalServerKeyFile         string
}

// Browser provides the authentication code flow using the browser.
type Browser struct {
	Browser browser.Interface
	Logger  logger.Interface
}

func (u *Browser) Do(ctx context.Context, o *BrowserOption, oidcClient client.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the authentication code flow using the browser")
	state, err := oidc.NewState()
	if err != nil {
		return nil, fmt.Errorf("could not generate a state: %w", err)
	}
	nonce, err := oidc.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("could not generate a nonce: %w", err)
	}
	p, err := pkce.New(oidcClient.SupportedPKCEMethods())
	if err != nil {
		return nil, fmt.Errorf("could not generate PKCE parameters: %w", err)
	}
	successHTML := BrowserSuccessHTML
	if o.OpenURLAfterAuthentication != "" {
		successHTML = BrowserRedirectHTML(o.OpenURLAfterAuthentication)
	}
	in := client.GetTokenByAuthCodeInput{
		BindAddress:            o.BindAddress,
		State:                  state,
		Nonce:                  nonce,
		PKCEParams:             p,
		RedirectURLHostname:    o.RedirectURLHostname,
		AuthRequestExtraParams: o.AuthRequestExtraParams,
		LocalServerSuccessHTML: successHTML,
		LocalServerCertFile:    o.LocalServerCertFile,
		LocalServerKeyFile:     o.LocalServerKeyFile,
	}

	ctx, cancel := context.WithTimeout(ctx, o.AuthenticationTimeout)
	defer cancel()
	readyChan := make(chan string, 1)
	var out *oidc.TokenSet
	var eg errgroup.Group
	eg.Go(func() error {
		select {
		case url, ok := <-readyChan:
			if !ok {
				return nil
			}
			u.openURL(ctx, o, url)
			return nil
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for the local server: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		defer close(readyChan)
		tokenSet, err := oidcClient.GetTokenByAuthCode(ctx, in, readyChan)
		if err != nil {
			return fmt.Errorf("authorization code flow error: %w", err)
		}
		out = tokenSet
		u.Logger.V(1).Infof("got a token set by the authorization code flow")
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("authentication error: %w", err)
	}
	u.Logger.V(1).Infof("finished the authorization code flow via the browser")
	return out, nil
}

func (u *Browser) openURL(ctx context.Context, o *BrowserOption, url string) {
	if o.SkipOpenBrowser {
		u.Logger.Printf("Please visit the following URL in your browser: %s", url)
		return
	}

	u.Logger.V(1).Infof("opening %s in the browser", url)
	if o.BrowserCommand != "" {
		if err := u.Browser.OpenCommand(ctx, url, o.BrowserCommand); err != nil {
			u.Logger.Printf(`error: could not open the browser: %s

Please visit the following URL in your browser manually: %s`, err, url)
		}
		return
	}
	if err := u.Browser.Open(url); err != nil {
		u.Logger.Printf(`error: could not open the browser: %s

Please visit the following URL in your browser manually: %s`, err, url)
	}
}
