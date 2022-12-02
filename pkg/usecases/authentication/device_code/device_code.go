package device_code

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"golang.org/x/oauth2"
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

var errExpired = errors.New("device request expired")

func (u *DeviceCode) Do(ctx context.Context, in *Option, oidcClient client.Interface) (*oidc.TokenSet, error) {
	u.Logger.V(1).Infof("starting the oauth2 device code flow")

	dr, err := oidcClient.GetDeviceAuthorization(ctx)
	if err != nil {
		return nil, err
	}

	if dr.VerificationURIComplete == "" {
		u.Logger.Printf("Please enter the following code when asked in your browser: %s", dr.UserCode)
		u.openURL(ctx, in, dr.VerificationURI)
	} else {
		u.openURL(ctx, in, dr.VerificationURIComplete)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(dr.ExpiresIn)*time.Second)
	defer cancel()

	fetchTicker := time.NewTicker(time.Duration(dr.Interval) * time.Second)

	defer fetchTicker.Stop()

	for {
		select {
		case <-fetchTicker.C:
			tokenSet, err := oidcClient.ExchangeDeviceCode(ctx, dr.DeviceCode)
			if err == nil {
				u.Logger.V(1).Infof("finished the oauth2 device code flow")
				return tokenSet, nil
			}
			u.Logger.V(1).Infof("err:", err)
			var errData struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			if retrieveTokenError, ok := err.(*oauth2.RetrieveError); ok {
				if err := json.Unmarshal(retrieveTokenError.Body, &errData); err != nil {
					u.Logger.V(1).Infof("unable to decode error response")
				}
			}
			switch errData.Error {
			case "authorization_pending":
				// we are still waiting
			case "slow_down":
				dr.Interval += 5
				fetchTicker.Reset(time.Duration(dr.Interval) * time.Second)
			default:
				return nil, fmt.Errorf("unable to fetch token (error %s: %q): %w", errData.Error, errData.ErrorDescription, err)
			}

		case <-ctx.Done():
			return nil, fmt.Errorf("unable to fetch token / timeout: %w", errExpired)
		}
	}
}

func (u *DeviceCode) openURL(ctx context.Context, o *Option, url string) {
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
