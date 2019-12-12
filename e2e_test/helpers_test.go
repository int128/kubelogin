package e2e_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/e2e_test/idp"
	"github.com/int128/kubelogin/e2e_test/idp/mock_idp"
	"github.com/int128/kubelogin/e2e_test/keys"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
)

var (
	tokenExpiryFuture = time.Now().Add(time.Hour).Round(time.Second)
	tokenExpiryPast   = time.Now().Add(-time.Hour).Round(time.Second)
)

func newIDToken(t *testing.T, issuer, nonce string, expiry time.Time) string {
	t.Helper()
	var claims struct {
		jwt.StandardClaims
		Nonce  string   `json:"nonce"`
		Groups []string `json:"groups"`
	}
	claims.StandardClaims = jwt.StandardClaims{
		Issuer:    issuer,
		Audience:  "kubernetes",
		Subject:   "SUBJECT",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: expiry.Unix(),
	}
	claims.Nonce = nonce
	claims.Groups = []string{"admin", "users"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(keys.JWSKeyPair)
	if err != nil {
		t.Fatalf("Could not sign the claims: %s", err)
	}
	return s
}

func setupMockIDPForCodeFlow(t *testing.T, service *mock_idp.MockService, serverURL, scope string, idToken *string) {
	var nonce string
	service.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
	service.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
	service.EXPECT().AuthenticateCode(scope, gomock.Any()).
		DoAndReturn(func(_, gotNonce string) (string, error) {
			nonce = gotNonce
			return "YOUR_AUTH_CODE", nil
		})
	service.EXPECT().Exchange("YOUR_AUTH_CODE").
		DoAndReturn(func(string) (*idp.TokenResponse, error) {
			*idToken = newIDToken(t, serverURL, nonce, tokenExpiryFuture)
			return idp.NewTokenResponse(*idToken, "YOUR_REFRESH_TOKEN"), nil
		})
}

func setupMockIDPForROPC(service *mock_idp.MockService, serverURL, scope, username, password, idToken string) {
	service.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
	service.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
	service.EXPECT().AuthenticatePassword(username, password, scope).
		Return(idp.NewTokenResponse(idToken, "YOUR_REFRESH_TOKEN"), nil)
}

func openBrowserOnReadyFunc(t *testing.T, ctx context.Context, clientConfig *tls.Config) authentication.LocalServerReadyFunc {
	return func(url string) {
		client := http.Client{Transport: &http.Transport{TLSClientConfig: clientConfig}}
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
	}
}
