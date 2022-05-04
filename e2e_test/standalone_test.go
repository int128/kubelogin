package e2e_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/pipedrive/kubelogin/e2e_test/idp"
	"github.com/pipedrive/kubelogin/e2e_test/idp/mock_idp"
	"github.com/pipedrive/kubelogin/e2e_test/keys"
	"github.com/pipedrive/kubelogin/e2e_test/kubeconfig"
	"github.com/pipedrive/kubelogin/e2e_test/localserver"
	"github.com/pipedrive/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/pipedrive/kubelogin/pkg/di"
	"github.com/pipedrive/kubelogin/pkg/usecases/authentication"
)

var (
	tokenExpiryFuture = time.Now().Add(time.Hour).Round(time.Second)
	tokenExpiryPast   = time.Now().Add(-time.Hour).Round(time.Second)
)

// Run the integration tests of the Login use-case.
//
// 1. Start the auth server.
// 2. Run the Cmd.
// 3. Open a request for the local server.
// 4. Verify the kubeconfig.
//
func TestCmd_Run_Standalone(t *testing.T) {
	timeout := 5 * time.Second

	type testParameter struct {
		startServer                       func(t *testing.T, h http.Handler) (string, localserver.Shutdowner)
		kubeconfigIDPCertificateAuthority string
		clientTLSConfig                   *tls.Config
	}

	testParameters := map[string]testParameter{
		"NoTLS": {
			startServer: localserver.Start,
		},
		"CACert": {
			startServer: func(t *testing.T, h http.Handler) (string, localserver.Shutdowner) {
				return localserver.StartTLS(t, keys.TLSServerCert, keys.TLSServerKey, h)
			},
			kubeconfigIDPCertificateAuthority: keys.TLSCACert,
			clientTLSConfig:                   keys.TLSCACertAsConfig,
		},
	}

	runTest := func(t *testing.T, p testParameter) {
		t.Run("Defaults", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			service := mock_idp.NewMockService(ctrl)
			serverURL, server := p.startServer(t, idp.NewHandler(t, service))
			defer server.Shutdown(t, ctx)
			var idToken string
			setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)

			kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
				Issuer:                  serverURL,
				IDPCertificateAuthority: p.kubeconfigIDPCertificateAuthority,
			})
			defer os.Remove(kubeConfigFilename)

			runCmd(t, ctx,
				openBrowserOnReadyFunc(t, ctx, p.clientTLSConfig),
				"--kubeconfig", kubeConfigFilename, "--skip-open-browser", "--listen-port", "0")
			kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
				IDToken:      idToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			})
		})

		t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			service := mock_idp.NewMockService(ctrl)
			serverURL, server := p.startServer(t, idp.NewHandler(t, service))
			defer server.Shutdown(t, ctx)
			idToken := newIDToken(t, serverURL, "", tokenExpiryFuture)
			service.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
			service.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
			service.EXPECT().AuthenticatePassword("USER", "PASS", "openid").
				Return(idp.NewTokenResponse(idToken, "YOUR_REFRESH_TOKEN"), nil)

			kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
				Issuer:                  serverURL,
				IDPCertificateAuthority: p.kubeconfigIDPCertificateAuthority,
			})
			defer os.Remove(kubeConfigFilename)

			runCmd(t, ctx,
				openBrowserOnReadyFunc(t, ctx, p.clientTLSConfig),
				"--kubeconfig", kubeConfigFilename, "--skip-open-browser", "--username", "USER", "--password", "PASS")
			kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
				IDToken:      idToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			})
		})

		t.Run("HasValidToken", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			service := mock_idp.NewMockService(ctrl)
			serverURL, server := p.startServer(t, idp.NewHandler(t, service))
			defer server.Shutdown(t, ctx)
			idToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)

			kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
				Issuer:                  serverURL,
				IDToken:                 idToken,
				RefreshToken:            "YOUR_REFRESH_TOKEN",
				IDPCertificateAuthority: p.kubeconfigIDPCertificateAuthority,
			})
			defer os.Remove(kubeConfigFilename)

			runCmd(t, ctx,
				openBrowserOnReadyFunc(t, ctx, p.clientTLSConfig),
				"--kubeconfig", kubeConfigFilename, "--skip-open-browser")
			kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
				IDToken:      idToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			})
		})

		t.Run("HasValidRefreshToken", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			service := mock_idp.NewMockService(ctrl)
			serverURL, server := p.startServer(t, idp.NewHandler(t, service))
			defer server.Shutdown(t, ctx)
			idToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
			service.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
			service.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
			service.EXPECT().Refresh("VALID_REFRESH_TOKEN").
				Return(idp.NewTokenResponse(idToken, "NEW_REFRESH_TOKEN"), nil)

			kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
				Issuer:                  serverURL,
				IDToken:                 newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast), // expired
				RefreshToken:            "VALID_REFRESH_TOKEN",
				IDPCertificateAuthority: p.kubeconfigIDPCertificateAuthority,
			})
			defer os.Remove(kubeConfigFilename)

			runCmd(t, ctx,
				openBrowserOnReadyFunc(t, ctx, p.clientTLSConfig),
				"--kubeconfig", kubeConfigFilename, "--skip-open-browser")
			kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
				IDToken:      idToken,
				RefreshToken: "NEW_REFRESH_TOKEN",
			})
		})

		t.Run("HasExpiredRefreshToken", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			service := mock_idp.NewMockService(ctrl)
			serverURL, server := p.startServer(t, idp.NewHandler(t, service))
			defer server.Shutdown(t, ctx)
			var idToken string
			setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)
			service.EXPECT().Refresh("EXPIRED_REFRESH_TOKEN").
				Return(nil, &idp.ErrorResponse{Code: "invalid_request", Description: "token has expired"}).
				MaxTimes(2) // package oauth2 will retry refreshing the token

			kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
				Issuer:                  serverURL,
				IDToken:                 newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast), // expired
				RefreshToken:            "EXPIRED_REFRESH_TOKEN",
				IDPCertificateAuthority: p.kubeconfigIDPCertificateAuthority,
			})
			defer os.Remove(kubeConfigFilename)

			runCmd(t, ctx,
				openBrowserOnReadyFunc(t, ctx, p.clientTLSConfig),
				"--kubeconfig", kubeConfigFilename, "--skip-open-browser")
			kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
				IDToken:      idToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			})
		})
	}

	for name, p := range testParameters {
		t.Run(name, func(t *testing.T) {
			runTest(t, p)
		})
	}

	t.Run("env:KUBECONFIG", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service))
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{Issuer: serverURL})
		defer os.Remove(kubeConfigFilename)
		setenv(t, "KUBECONFIG", kubeConfigFilename+string(os.PathListSeparator)+"kubeconfig/testdata/dummy.yaml")
		defer unsetenv(t, "KUBECONFIG")

		runCmd(t, ctx,
			openBrowserOnReadyFunc(t, ctx, nil),
			"--skip-open-browser", "--listen-port", "0")
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service))
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "profile groups openid", &idToken)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:      serverURL,
			ExtraScopes: "profile,groups",
		})
		defer os.Remove(kubeConfigFilename)

		runCmd(t, ctx,
			openBrowserOnReadyFunc(t, ctx, nil),
			"--kubeconfig", kubeConfigFilename, "--skip-open-browser", "--listen-port", "0")
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})
	})
}

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

func runCmd(t *testing.T, ctx context.Context, localServerReadyFunc authentication.LocalServerReadyFunc, args ...string) {
	t.Helper()
	cmd := di.NewCmdForHeadless(mock_logger.New(t), localServerReadyFunc, nil)
	exitCode := cmd.Run(ctx, append([]string{"kubelogin", "--v=1"}, args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
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

func setenv(t *testing.T, key, value string) {
	t.Helper()
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("Could not set the env var %s=%s: %s", key, value, err)
	}
}

func unsetenv(t *testing.T, key string) {
	t.Helper()
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Could not unset the env var %s: %s", key, err)
	}
}
