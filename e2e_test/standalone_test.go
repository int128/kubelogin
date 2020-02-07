package e2e_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/e2e_test/idp"
	"github.com/int128/kubelogin/e2e_test/idp/mock_idp"
	"github.com/int128/kubelogin/e2e_test/keys"
	"github.com/int128/kubelogin/e2e_test/kubeconfig"
	"github.com/int128/kubelogin/e2e_test/localserver"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/browser/mock_browser"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/di"
)

// Run the integration tests of the Login use-case.
//
// 1. Start the auth server.
// 2. Run the Cmd.
// 3. Open a request for the local server.
// 4. Verify the kubeconfig.
//
func TestStandalone(t *testing.T) {
	t.Run("NoTLS", func(t *testing.T) {
		testStandalone(t, keys.None)
	})
	t.Run("TLS", func(t *testing.T) {
		testStandalone(t, keys.Server)
	})
}

func testStandalone(t *testing.T, idpTLS keys.Keys) {
	timeout := 5 * time.Second

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverURL,
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)

		args := []string{
			"--kubeconfig", kubeConfigFilename,
		}
		runRootCmd(t, ctx, browserMock, args)
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		browserMock := mock_browser.NewMockInterface(ctrl)
		idToken := newIDToken(t, serverURL, "", tokenExpiryFuture)
		setupMockIDPForROPC(service, serverURL, "openid", "USER", "PASS", idToken)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverURL,
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)

		args := []string{
			"--kubeconfig", kubeConfigFilename,
			"--username", "USER",
			"--password", "PASS",
		}
		runRootCmd(t, ctx, browserMock, args)
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		idToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
		browserMock := mock_browser.NewMockInterface(ctrl)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverURL,
			IDToken:                 idToken,
			RefreshToken:            "YOUR_REFRESH_TOKEN",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)

		args := []string{
			"--kubeconfig", kubeConfigFilename,
		}
		runRootCmd(t, ctx, browserMock, args)
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		idToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
		service.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
		service.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
		service.EXPECT().Refresh("VALID_REFRESH_TOKEN").
			Return(idp.NewTokenResponse(idToken, "NEW_REFRESH_TOKEN"), nil)
		browserMock := mock_browser.NewMockInterface(ctrl)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverURL,
			IDToken:                 newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast), // expired
			RefreshToken:            "VALID_REFRESH_TOKEN",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)

		args := []string{
			"--kubeconfig", kubeConfigFilename,
		}
		runRootCmd(t, ctx, browserMock, args)
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)
		service.EXPECT().Refresh("EXPIRED_REFRESH_TOKEN").
			Return(nil, &idp.ErrorResponse{Code: "invalid_request", Description: "token has expired"}).
			MaxTimes(2) // package oauth2 will retry refreshing the token
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverURL,
			IDToken:                 newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast), // expired
			RefreshToken:            "EXPIRED_REFRESH_TOKEN",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)

		args := []string{
			"--kubeconfig", kubeConfigFilename,
		}
		runRootCmd(t, ctx, browserMock, args)
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})
	})

	t.Run("env_KUBECONFIG", func(t *testing.T) {
		// do not run this in parallel due to change of the env var
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		service := mock_idp.NewMockService(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "openid", &idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverURL,
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		setenv(t, "KUBECONFIG", kubeConfigFilename+string(os.PathListSeparator)+"kubeconfig/testdata/dummy.yaml")
		defer unsetenv(t, "KUBECONFIG")

		args := []string{
			"--kubeconfig", kubeConfigFilename,
		}
		runRootCmd(t, ctx, browserMock, args)
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, service), idpTLS)
		defer server.Shutdown(t, ctx)
		var idToken string
		setupMockIDPForCodeFlow(t, service, serverURL, "profile groups openid", &idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverURL,
			ExtraScopes:             "profile,groups",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)

		args := []string{
			"--kubeconfig", kubeConfigFilename,
		}
		runRootCmd(t, ctx, browserMock, args)
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})
	})
}

func runRootCmd(t *testing.T, ctx context.Context, b browser.Interface, args []string) {
	t.Helper()
	cmd := di.NewCmdForHeadless(mock_logger.New(t), b, nil)
	exitCode := cmd.Run(ctx, append([]string{
		"kubelogin",
		"--v=1",
		"--listen-address", "127.0.0.1:0",
	}, args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
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
