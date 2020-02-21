package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/integration_test/idp"
	"github.com/int128/kubelogin/integration_test/idp/mock_idp"
	"github.com/int128/kubelogin/integration_test/keys"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/browser/mock_browser"
)

var (
	tokenExpiryFuture = time.Now().Add(time.Hour).Round(time.Second)
	tokenExpiryPast   = time.Now().Add(-time.Hour).Round(time.Second)
)

func newIDToken(t *testing.T, issuer, nonce string, expiry time.Time) string {
	t.Helper()
	var claims struct {
		jwt.StandardClaims
		// aud claim is either a string or an array of strings.
		// https://tools.ietf.org/html/rfc7519#section-4.1.3
		Audience []string `json:"aud"`
		Nonce    string   `json:"nonce"`
		Groups   []string `json:"groups"`
	}
	claims.Issuer = issuer
	claims.Subject = "SUBJECT"
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = expiry.Unix()
	claims.Audience = []string{"kubernetes", "system"}
	claims.Nonce = nonce
	claims.Groups = []string{"admin", "users"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(keys.JWSKeyPair)
	if err != nil {
		t.Fatalf("Could not sign the claims: %s", err)
	}
	return s
}

func setupAuthCodeFlow(t *testing.T, provider *mock_idp.MockProvider, serverURL, scope string, idToken *string) {
	var nonce string
	provider.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
	provider.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
	provider.EXPECT().AuthenticateCode(scope, gomock.Any()).
		DoAndReturn(func(_, gotNonce string) (string, error) {
			nonce = gotNonce
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
	provider.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
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
