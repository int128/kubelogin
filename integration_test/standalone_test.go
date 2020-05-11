package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/kubeconfig"
	"github.com/int128/kubelogin/integration_test/oidcserver"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/browser/mock_browser"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/testing/logger"
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
		testStandalone(t, keypair.None)
	})
	t.Run("TLS", func(t *testing.T) {
		testStandalone(t, keypair.Server)
	})
}

func testStandalone(t *testing.T, idpTLS keypair.KeyPair) {
	timeout := 5 * time.Second

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  server.IssuerURL(),
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		runRootCmd(t, ctx, browserMock, []string{
			"--kubeconfig", kubeConfigFilename,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})
	})

	t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			Username:          "USER",
			Password:          "PASS",
		})
		defer server.Shutdown(t, ctx)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  server.IssuerURL(),
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		browserMock := mock_browser.NewMockInterface(ctrl)
		runRootCmd(t, ctx, browserMock, []string{
			"--kubeconfig", kubeConfigFilename,
			"--username", "USER",
			"--password", "PASS",
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})
	})

	t.Run("HasValidToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		browserMock := mock_browser.NewMockInterface(ctrl)
		idToken := server.NewTokenResponse(tokenExpiryFuture, "YOUR_NONCE").IDToken
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  server.IssuerURL(),
			IDToken:                 idToken,
			RefreshToken:            "YOUR_REFRESH_TOKEN",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		runRootCmd(t, ctx, browserMock, []string{
			"--kubeconfig", kubeConfigFilename,
		})
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

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			RefreshToken:      "VALID_REFRESH_TOKEN",
		})
		browserMock := mock_browser.NewMockInterface(ctrl)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  server.IssuerURL(),
			IDToken:                 server.NewTokenResponse(tokenExpiryPast, "YOUR_NONCE").IDToken, // expired
			RefreshToken:            "VALID_REFRESH_TOKEN",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		runRootCmd(t, ctx, browserMock, []string{
			"--kubeconfig", kubeConfigFilename,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
	})

	t.Run("HasExpiredRefreshToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			RefreshToken:      "EXPIRED_REFRESH_TOKEN",
			RefreshError:      "token has expired",
		})
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)
		expired := server.NewTokenResponse(tokenExpiryPast, "EXPIRED_NONCE")
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  server.IssuerURL(),
			IDToken:                 expired.IDToken,
			RefreshToken:            "EXPIRED_REFRESH_TOKEN",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		runRootCmd(t, ctx, browserMock, []string{
			"--kubeconfig", kubeConfigFilename,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
	})

	t.Run("env_KUBECONFIG", func(t *testing.T) {
		// do not run this in parallel due to change of the env var
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  server.IssuerURL(),
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		setenv(t, "KUBECONFIG", kubeConfigFilename+string(os.PathListSeparator)+"kubeconfig/testdata/dummy.yaml")
		defer unsetenv(t, "KUBECONFIG")
		runRootCmd(t, ctx, browserMock, []string{
			"--kubeconfig", kubeConfigFilename,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "profile groups openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  server.IssuerURL(),
			ExtraScopes:             "profile,groups",
			IDPCertificateAuthority: idpTLS.CACertPath,
		})
		defer os.Remove(kubeConfigFilename)
		runRootCmd(t, ctx, browserMock, []string{
			"--kubeconfig", kubeConfigFilename,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
	})
}

func runRootCmd(t *testing.T, ctx context.Context, b browser.Interface, args []string) {
	t.Helper()
	cmd := di.NewCmdForHeadless(logger.New(t), b, nil)
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
