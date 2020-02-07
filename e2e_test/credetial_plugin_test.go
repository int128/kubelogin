package e2e_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/e2e_test/idp"
	"github.com/int128/kubelogin/e2e_test/idp/mock_idp"
	"github.com/int128/kubelogin/e2e_test/keys"
	"github.com/int128/kubelogin/e2e_test/localserver"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/browser/mock_browser"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter/mock_credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/di"
)

// Run the integration tests of the credential plugin use-case.
//
// 1. Start the auth server.
// 2. Run the Cmd.
// 3. Open a request for the local server.
// 4. Verify the output.
//
func TestCredentialPlugin(t *testing.T) {
	cacheDir, err := ioutil.TempDir("", "kube")
	if err != nil {
		t.Fatalf("could not create a cache dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cacheDir); err != nil {
			t.Errorf("could not clean up the cache dir: %s", err)
		}
	}()

	t.Run("NoTLS", func(t *testing.T) {
		testCredentialPlugin(t, cacheDir, keys.None, nil)
	})
	t.Run("TLS", func(t *testing.T) {
		testCredentialPlugin(t, cacheDir, keys.Server, []string{"--certificate-authority", keys.Server.CACertPath})
	})
}

func testCredentialPlugin(t *testing.T, cacheDir string, idpTLS keys.Keys, extraArgs []string) {
	timeout := 1 * time.Second

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), idpTLS)
		defer server.Shutdown(t, ctx)
		var idToken string
		setupAuthCodeFlow(t, provider, serverURL, "openid", &idToken)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
	})

	t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), idpTLS)
		defer server.Shutdown(t, ctx)
		idToken := newIDToken(t, serverURL, "", tokenExpiryFuture)
		setupROPCFlow(provider, serverURL, "openid", "USER", "PASS", idToken)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &idToken)
		browserMock := mock_browser.NewMockInterface(ctrl)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--username", "USER",
			"--password", "PASS",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
	})

	t.Run("HasValidToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), idpTLS)
		defer server.Shutdown(t, ctx)
		idToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
		setupTokenCache(t, cacheDir,
			tokencache.Key{
				IssuerURL:      serverURL,
				ClientID:       "kubernetes",
				CACertFilename: idpTLS.CACertPath,
			}, tokencache.Value{
				IDToken:      idToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			})
		writerMock := newCredentialPluginWriterMock(t, ctrl, &idToken)
		browserMock := mock_browser.NewMockInterface(ctrl)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
		assertTokenCache(t, cacheDir,
			tokencache.Key{
				IssuerURL:      serverURL,
				ClientID:       "kubernetes",
				CACertFilename: idpTLS.CACertPath,
			}, tokencache.Value{
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

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), idpTLS)
		defer server.Shutdown(t, ctx)
		validIDToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
		expiredIDToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast)

		provider.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
		provider.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(keys.JWSKeyPair))
		provider.EXPECT().Refresh("VALID_REFRESH_TOKEN").
			Return(idp.NewTokenResponse(validIDToken, "NEW_REFRESH_TOKEN"), nil)

		setupTokenCache(t, cacheDir,
			tokencache.Key{
				IssuerURL:      serverURL,
				ClientID:       "kubernetes",
				CACertFilename: idpTLS.CACertPath,
			}, tokencache.Value{
				IDToken:      expiredIDToken,
				RefreshToken: "VALID_REFRESH_TOKEN",
			})
		writerMock := newCredentialPluginWriterMock(t, ctrl, &validIDToken)
		browserMock := mock_browser.NewMockInterface(ctrl)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
		assertTokenCache(t, cacheDir,
			tokencache.Key{
				IssuerURL:      serverURL,
				ClientID:       "kubernetes",
				CACertFilename: idpTLS.CACertPath,
			}, tokencache.Value{
				IDToken:      validIDToken,
				RefreshToken: "NEW_REFRESH_TOKEN",
			})
	})

	t.Run("HasExpiredRefreshToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), idpTLS)
		defer server.Shutdown(t, ctx)
		validIDToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
		expiredIDToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast)

		setupAuthCodeFlow(t, provider, serverURL, "openid", &validIDToken)
		provider.EXPECT().Refresh("EXPIRED_REFRESH_TOKEN").
			Return(nil, &idp.ErrorResponse{Code: "invalid_request", Description: "token has expired"}).
			MaxTimes(2) // package oauth2 will retry refreshing the token

		setupTokenCache(t, cacheDir,
			tokencache.Key{
				IssuerURL:      serverURL,
				ClientID:       "kubernetes",
				CACertFilename: idpTLS.CACertPath,
			}, tokencache.Value{
				IDToken:      expiredIDToken,
				RefreshToken: "EXPIRED_REFRESH_TOKEN",
			})
		writerMock := newCredentialPluginWriterMock(t, ctrl, &validIDToken)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
		assertTokenCache(t, cacheDir,
			tokencache.Key{
				IssuerURL:      serverURL,
				ClientID:       "kubernetes",
				CACertFilename: idpTLS.CACertPath,
			}, tokencache.Value{
				IDToken:      validIDToken,
				RefreshToken: "YOUR_REFRESH_TOKEN",
			})
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), idpTLS)
		defer server.Shutdown(t, ctx)
		var idToken string
		setupAuthCodeFlow(t, provider, serverURL, "email profile openid", &idToken)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, idpTLS)

		args := []string{
			"--token-cache-dir", cacheDir,
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--oidc-extra-scope", "email",
			"--oidc-extra-scope", "profile",
		}
		args = append(args, extraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
	})
}

func newCredentialPluginWriterMock(t *testing.T, ctrl *gomock.Controller, idToken *string) *mock_credentialpluginwriter.MockInterface {
	writer := mock_credentialpluginwriter.NewMockInterface(ctrl)
	writer.EXPECT().
		Write(gomock.Any()).
		Do(func(got credentialpluginwriter.Output) {
			want := credentialpluginwriter.Output{
				Token:  *idToken,
				Expiry: tokenExpiryFuture,
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	return writer
}

func runGetTokenCmd(t *testing.T, ctx context.Context, b browser.Interface, interaction credentialpluginwriter.Interface, args []string) {
	t.Helper()
	cmd := di.NewCmdForHeadless(mock_logger.New(t), b, interaction)
	exitCode := cmd.Run(ctx, append([]string{
		"kubelogin", "get-token",
		"--v=1",
		"--listen-address", "127.0.0.1:0",
	}, args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}

func setupTokenCache(t *testing.T, cacheDir string, k tokencache.Key, v tokencache.Value) {
	var r tokencache.Repository
	err := r.Save(cacheDir, k, v)
	if err != nil {
		t.Errorf("could not set up the token cache: %s", err)
	}
}

func assertTokenCache(t *testing.T, cacheDir string, k tokencache.Key, want tokencache.Value) {
	var r tokencache.Repository
	got, err := r.FindByKey(cacheDir, k)
	if err != nil {
		t.Errorf("could not set up the token cache: %s", err)
	}
	if diff := cmp.Diff(&want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
