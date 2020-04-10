package integration_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/integration_test/idp"
	"github.com/int128/kubelogin/integration_test/idp/mock_idp"
	"github.com/int128/kubelogin/integration_test/keys"
	"github.com/int128/kubelogin/integration_test/localserver"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/browser/mock_browser"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter/mock_credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
)

// Run the integration tests of the credential plugin use-case.
//
// 1. Start the auth server.
// 2. Run the Cmd.
// 3. Open a request for the local server.
// 4. Verify the output.
//
func TestCredentialPlugin(t *testing.T) {
	tokenCacheDir, err := ioutil.TempDir("", "kube")
	if err != nil {
		t.Fatalf("could not create a cache dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(tokenCacheDir); err != nil {
			t.Errorf("could not clean up the cache dir: %s", err)
		}
	}()

	t.Run("NoTLS", func(t *testing.T) {
		testCredentialPlugin(t, credentialPluginTestCase{
			TokenCacheDir: tokenCacheDir,
			Keys:          keys.None,
			ExtraArgs: []string{
				"--token-cache-dir", tokenCacheDir,
			},
		})
	})
	t.Run("TLS", func(t *testing.T) {
		t.Run("CertFile", func(t *testing.T) {
			testCredentialPlugin(t, credentialPluginTestCase{
				TokenCacheDir: tokenCacheDir,
				TokenCacheKey: tokencache.Key{CACertFilename: keys.Server.CACertPath},
				Keys:          keys.Server,
				ExtraArgs: []string{
					"--token-cache-dir", tokenCacheDir,
					"--certificate-authority", keys.Server.CACertPath,
				},
			})
		})
		t.Run("CertData", func(t *testing.T) {
			testCredentialPlugin(t, credentialPluginTestCase{
				TokenCacheDir: tokenCacheDir,
				TokenCacheKey: tokencache.Key{CACertData: keys.Server.CACertBase64},
				Keys:          keys.Server,
				ExtraArgs: []string{
					"--token-cache-dir", tokenCacheDir,
					"--certificate-authority-data", keys.Server.CACertBase64,
				},
			})
		})
	})
}

type credentialPluginTestCase struct {
	TokenCacheDir string
	TokenCacheKey tokencache.Key
	Keys          keys.Keys
	ExtraArgs     []string
}

func testCredentialPlugin(t *testing.T, tc credentialPluginTestCase) {
	timeout := 1 * time.Second

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)
		cfg := authCodeFlowConfig{
			serverURL:         serverURL,
			scope:             "openid",
			redirectURIPrefix: "http://localhost:",
		}
		setupAuthCodeFlow(t, provider, &cfg)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &cfg.idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, tc.Keys)

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, tc.ExtraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
	})

	t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)
		idToken := newIDToken(t, serverURL, "", tokenExpiryFuture)
		setupROPCFlow(provider, serverURL, "openid", "USER", "PASS", idToken)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &idToken)
		browserMock := mock_browser.NewMockInterface(ctrl)

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--username", "USER",
			"--password", "PASS",
		}
		args = append(args, tc.ExtraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
	})

	t.Run("HasValidToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)
		idToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &idToken)
		browserMock := mock_browser.NewMockInterface(ctrl)
		setupTokenCache(t, tc, serverURL, tokencache.Value{
			IDToken:      idToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, tc.ExtraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
		assertTokenCache(t, tc, serverURL, tokencache.Value{
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)
		validIDToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryFuture)
		expiredIDToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast)

		provider.EXPECT().Discovery().Return(idp.NewDiscoveryResponse(serverURL))
		provider.EXPECT().GetCertificates().Return(idp.NewCertificatesResponse(jwt.PrivateKey))
		provider.EXPECT().Refresh("VALID_REFRESH_TOKEN").
			Return(idp.NewTokenResponse(validIDToken, "NEW_REFRESH_TOKEN"), nil)

		setupTokenCache(t, tc, serverURL, tokencache.Value{
			IDToken:      expiredIDToken,
			RefreshToken: "VALID_REFRESH_TOKEN",
		})
		writerMock := newCredentialPluginWriterMock(t, ctrl, &validIDToken)
		browserMock := mock_browser.NewMockInterface(ctrl)

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, tc.ExtraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
		assertTokenCache(t, tc, serverURL, tokencache.Value{
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)

		cfg := authCodeFlowConfig{
			serverURL:         serverURL,
			scope:             "openid",
			redirectURIPrefix: "http://localhost:",
		}
		setupAuthCodeFlow(t, provider, &cfg)
		provider.EXPECT().Refresh("EXPIRED_REFRESH_TOKEN").
			Return(nil, &idp.ErrorResponse{Code: "invalid_request", Description: "token has expired"}).
			MaxTimes(2) // package oauth2 will retry refreshing the token

		expiredIDToken := newIDToken(t, serverURL, "YOUR_NONCE", tokenExpiryPast)
		setupTokenCache(t, tc, serverURL, tokencache.Value{
			IDToken:      expiredIDToken,
			RefreshToken: "EXPIRED_REFRESH_TOKEN",
		})
		writerMock := newCredentialPluginWriterMock(t, ctrl, &cfg.idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, tc.Keys)

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
		}
		args = append(args, tc.ExtraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
		assertTokenCache(t, tc, serverURL, tokencache.Value{
			IDToken:      cfg.idToken,
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
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)
		cfg := authCodeFlowConfig{
			serverURL:         serverURL,
			scope:             "email profile openid",
			redirectURIPrefix: "http://localhost:",
		}
		setupAuthCodeFlow(t, provider, &cfg)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &cfg.idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, tc.Keys)

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--oidc-extra-scope", "email",
			"--oidc-extra-scope", "profile",
		}
		args = append(args, tc.ExtraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
	})

	t.Run("RedirectURLHostname", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)
		cfg := authCodeFlowConfig{
			serverURL:         serverURL,
			scope:             "openid",
			redirectURIPrefix: "http://127.0.0.1:",
		}
		setupAuthCodeFlow(t, provider, &cfg)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &cfg.idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, tc.Keys)

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--oidc-redirect-url-hostname", "127.0.0.1",
		}
		args = append(args, tc.ExtraArgs...)
		runGetTokenCmd(t, ctx, browserMock, writerMock, args)
	})

	t.Run("ExtraParams", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		provider := mock_idp.NewMockProvider(ctrl)
		serverURL, server := localserver.Start(t, idp.NewHandler(t, provider), tc.Keys)
		defer server.Shutdown(t, ctx)
		cfg := authCodeFlowConfig{
			serverURL:         serverURL,
			scope:             "openid",
			redirectURIPrefix: "http://localhost:",
			extraParams: map[string]string{
				"ttl":    "86400",
				"reauth": "false",
			},
		}
		setupAuthCodeFlow(t, provider, &cfg)
		writerMock := newCredentialPluginWriterMock(t, ctrl, &cfg.idToken)
		browserMock := newBrowserMock(ctx, t, ctrl, tc.Keys)

		args := []string{
			"--oidc-issuer-url", serverURL,
			"--oidc-client-id", "kubernetes",
			"--oidc-auth-request-extra-params", "ttl=86400",
			"--oidc-auth-request-extra-params", "reauth=false",
		}
		args = append(args, tc.ExtraArgs...)
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

func runGetTokenCmd(t *testing.T, ctx context.Context, b browser.Interface, w credentialpluginwriter.Interface, args []string) {
	t.Helper()
	cmd := di.NewCmdForHeadless(logger.New(t), b, w)
	exitCode := cmd.Run(ctx, append([]string{
		"kubelogin", "get-token",
		"--v=1",
		"--listen-address", "127.0.0.1:0",
	}, args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}

func setupTokenCache(t *testing.T, tc credentialPluginTestCase, serverURL string, v tokencache.Value) {
	k := tc.TokenCacheKey
	k.IssuerURL = serverURL
	k.ClientID = "kubernetes"
	var r tokencache.Repository
	err := r.Save(tc.TokenCacheDir, k, v)
	if err != nil {
		t.Errorf("could not set up the token cache: %s", err)
	}
}

func assertTokenCache(t *testing.T, tc credentialPluginTestCase, serverURL string, want tokencache.Value) {
	k := tc.TokenCacheKey
	k.IssuerURL = serverURL
	k.ClientID = "kubernetes"
	var r tokencache.Repository
	got, err := r.FindByKey(tc.TokenCacheDir, k)
	if err != nil {
		t.Errorf("could not set up the token cache: %s", err)
	}
	if diff := cmp.Diff(&want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
