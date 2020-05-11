package integration_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/integration_test/httpdriver"
	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/oidcserver"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter/mock_credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/di"
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
			tokenCacheDir: tokenCacheDir,
			idpTLS:        keypair.None,
			extraArgs: []string{
				"--token-cache-dir", tokenCacheDir,
			},
		})
	})
	t.Run("TLS", func(t *testing.T) {
		t.Run("CertFile", func(t *testing.T) {
			testCredentialPlugin(t, credentialPluginTestCase{
				tokenCacheDir: tokenCacheDir,
				tokenCacheKey: tokencache.Key{CACertFilename: keypair.Server.CACertPath},
				idpTLS:        keypair.Server,
				extraArgs: []string{
					"--token-cache-dir", tokenCacheDir,
					"--certificate-authority", keypair.Server.CACertPath,
				},
			})
		})
		t.Run("CertData", func(t *testing.T) {
			testCredentialPlugin(t, credentialPluginTestCase{
				tokenCacheDir: tokenCacheDir,
				tokenCacheKey: tokencache.Key{CACertData: keypair.Server.CACertBase64},
				idpTLS:        keypair.Server,
				extraArgs: []string{
					"--token-cache-dir", tokenCacheDir,
					"--certificate-authority-data", keypair.Server.CACertBase64,
				},
			})
		})
	})
}

type credentialPluginTestCase struct {
	tokenCacheDir string
	tokenCacheKey tokencache.Key
	idpTLS        keypair.KeyPair
	extraArgs     []string
}

func testCredentialPlugin(t *testing.T, tc credentialPluginTestCase) {
	timeout := 1 * time.Second

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return server.LastTokenResponse().IDToken })
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
	})

	t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			Username:          "USER",
			Password:          "PASS",
		})
		defer server.Shutdown(t, ctx)
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return server.LastTokenResponse().IDToken })
		browserMock := httpdriver.Zero(t)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--username", "USER",
				"--password", "PASS",
			}, tc.extraArgs...))
	})

	t.Run("HasValidToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		idToken := server.NewTokenResponse(tokenExpiryFuture, "YOUR_NONCE").IDToken
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return idToken })
		browserMock := httpdriver.Zero(t)
		setupTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
			IDToken:      idToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		})
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
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
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			RefreshToken:      "VALID_REFRESH_TOKEN",
		})
		defer server.Shutdown(t, ctx)

		expired := server.NewTokenResponse(tokenExpiryPast, "EXPIRED_NONCE")
		setupTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
			IDToken:      expired.IDToken,
			RefreshToken: "VALID_REFRESH_TOKEN",
		})
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return server.LastTokenResponse().IDToken })
		browserMock := httpdriver.Zero(t)

		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
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
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			RefreshError:      "token has expired",
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			RefreshToken:      "EXPIRED_REFRESH_TOKEN",
		})
		defer server.Shutdown(t, ctx)

		expired := server.NewTokenResponse(tokenExpiryPast, "EXPIRED_NONCE")
		setupTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
			IDToken:      expired.IDToken,
			RefreshToken: "EXPIRED_REFRESH_TOKEN",
		})
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return server.LastTokenResponse().IDToken })
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
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
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "email profile openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return server.LastTokenResponse().IDToken })
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--oidc-extra-scope", "email",
				"--oidc-extra-scope", "profile",
			}, tc.extraArgs...))
	})

	t.Run("RedirectURLHostname", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://127.0.0.1:",
		})
		defer server.Shutdown(t, ctx)
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return server.LastTokenResponse().IDToken })
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--oidc-redirect-url-hostname", "127.0.0.1",
			}, tc.extraArgs...))
	})

	t.Run("ExtraParams", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			ExtraParams: map[string]string{
				"ttl":    "86400",
				"reauth": "false",
			},
		})
		defer server.Shutdown(t, ctx)
		writerMock := newCredentialPluginWriterMock(t, ctrl, func() string { return server.LastTokenResponse().IDToken })
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--oidc-auth-request-extra-params", "ttl=86400",
				"--oidc-auth-request-extra-params", "reauth=false",
			}, tc.extraArgs...))
	})
}

func newCredentialPluginWriterMock(t *testing.T, ctrl *gomock.Controller, idToken func() string) *mock_credentialpluginwriter.MockInterface {
	writer := mock_credentialpluginwriter.NewMockInterface(ctrl)
	writer.EXPECT().
		Write(gomock.Any()).
		Do(func(got credentialpluginwriter.Output) {
			want := credentialpluginwriter.Output{
				Token:  idToken(),
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
	k := tc.tokenCacheKey
	k.IssuerURL = serverURL
	k.ClientID = "kubernetes"
	var r tokencache.Repository
	err := r.Save(tc.tokenCacheDir, k, v)
	if err != nil {
		t.Errorf("could not set up the token cache: %s", err)
	}
}

func assertTokenCache(t *testing.T, tc credentialPluginTestCase, serverURL string, want tokencache.Value) {
	k := tc.tokenCacheKey
	k.IssuerURL = serverURL
	k.ClientID = "kubernetes"
	var r tokencache.Repository
	got, err := r.FindByKey(tc.tokenCacheDir, k)
	if err != nil {
		t.Errorf("could not set up the token cache: %s", err)
	}
	if diff := cmp.Diff(&want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
