package devicecode

import (
	"context"
	"fmt"

	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
)

type Option struct {
	SkipOpenBrowser bool
	BrowserCommand  string
}

// DeviceCode provides the oauth2 device code flow.
type DeviceCode struct {
	Browser browser.Interface
	Logger  logger.Interface
}

func (u *DeviceCode) Do(ctx context.Context, in *Option, oidcClient client.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the oauth2 device code flow")

	authResponse, err := oidcClient.GetDeviceAuthorization(ctx)
	if err != nil {
		return nil, fmt.Errorf("authorization error: %w", err)
	}

	if authResponse.VerificationURIComplete != "" {
		u.openURL(ctx, in, authResponse.VerificationURIComplete)
	} else if authResponse.VerificationURI != "" {
		u.Logger.Printf("Please enter the following code when asked in your browser: %s", authResponse.UserCode)
		u.openURL(ctx, in, authResponse.VerificationURI)
	} else if authResponse.VerificationURL != "" {
		u.Logger.Printf("Please enter the following code when asked in your browser: %s", authResponse.UserCode)
		u.openURL(ctx, in, authResponse.VerificationURL)
	} else {
		return nil, fmt.Errorf("no verification URI in the authorization response")
	}

	tokenSet, err := oidcClient.ExchangeDeviceCode(ctx, authResponse)
	u.Logger.V(1).Infof("finished the oauth2 device code flow")
	if err != nil {
		return nil, fmt.Errorf("unable to exchange device code: %w", err)
	}
	return tokenSet, nil
}

func (u *DeviceCode) openURL(ctx context.Context, o *Option, url string) {
	if o != nil && o.SkipOpenBrowser {
		u.Logger.Printf("Please visit the following URL in your browser: %s", url)
		return
	}

	u.Logger.V(1).Infof("opening %s in the browser", url)
	if o != nil && o.BrowserCommand != "" {
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
