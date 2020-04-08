package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/integration_test/idp"
	"github.com/int128/kubelogin/integration_test/idp/mock_idp"
	"github.com/int128/kubelogin/integration_test/keys"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/browser/mock_browser"
	"github.com/int128/kubelogin/pkg/testing/jwt"
)

var (
	tokenExpiryFuture = time.Now().Add(time.Hour).Round(time.Second)
	tokenExpiryPast   = time.Now().Add(-time.Hour).Round(time.Second)
)

func newIDToken(t *testing.T, issuer, nonce string, expiry time.Time) string {
	t.Helper()
	return jwt.EncodeF(t, func(claims *jwt.Claims) {
		claims.Issuer = issuer
		claims.Subject = "SUBJECT"
		claims.IssuedAt = time.Now().Unix()
		claims.ExpiresAt = expiry.Unix()
		claims.Audience = []string{"kubernetes", "system"}
		claims.Nonce = nonce
		claims.Groups = []string{"admin", "users"}
	})
}

func setupAuthCodeFlow(t *testing.T, provider *mock_idp.MockProvider, serverURL, scope, redirectURIPrefix string, extraParams map[string]string, idToken *string) {
	var nonce string
	provider.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
	provider.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(jwt.PrivateKey))
	provider.EXPECT().AuthenticateCode(gomock.Any()).
		DoAndReturn(func(req idp.AuthenticationRequest) (string, error) {
			if req.Scope != scope {
				t.Errorf("scope wants `%s` but was `%s`", scope, req.Scope)
			}
			if !strings.HasPrefix(req.RedirectURI, redirectURIPrefix) {
				t.Errorf("redirectURI wants prefix `%s` but was `%s`", redirectURIPrefix, req.RedirectURI)
			}
			for k, v := range extraParams {
				got := req.RawQuery.Get(k)
				if got != v {
					t.Errorf("parameter %s wants `%s` but was `%s`", k, v, got)
				}
			}
			nonce = req.Nonce
			return "YOUR_AUTH_CODE", nil
		})
	provider.EXPECT().Exchange("YOUR_AUTH_CODE").
		DoAndReturn(func(string) (*idp.TokenResponse, error) {
			*idToken = newIDToken(t, serverURL, nonce, tokenExpiryFuture)
			return idp.NewTokenResponse(*idToken, "YOUR_REFRESH_TOKEN"), nil
		})
}

func setupROPCFlow(provider *mock_idp.MockProvider, serverURL, scope, username, password, idToken string) {
	provider.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
	provider.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(jwt.PrivateKey))
	provider.EXPECT().AuthenticatePassword(username, password, scope).
		Return(idp.NewTokenResponse(idToken, "YOUR_REFRESH_TOKEN"), nil)
}

func newBrowserMock(ctx context.Context, t *testing.T, ctrl *gomock.Controller, k keys.Keys) browser.Interface {
	b := mock_browser.NewMockInterface(ctrl)
	b.EXPECT().
		Open(gomock.Any()).
		Do(func(url string) {
			client := http.Client{Transport: &http.Transport{TLSClientConfig: k.TLSConfig}}
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Errorf("could not create a request: %s", err)
				return
			}
			req = req.WithContext(ctx)
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("could not send a request: %s", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("StatusCode wants 200 but %d", resp.StatusCode)
			}
		})
	return b
}
