package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/integration_test/httpdriver"
	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/oidcserver"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
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
	var (
		tokenExpiryFuture = time.Now().Add(time.Hour).Round(time.Second)
		tokenExpiryPast   = time.Now().Add(-time.Hour).Round(time.Second)
	)

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
		assertCredentialPluginWriter(t, &stdout, server.LastTokenResponse().IDToken, tokenExpiryFuture)
	})

	t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			Username:          "USER",
			Password:          "PASS",
		})
		defer server.Shutdown(t, ctx)
		browserMock := httpdriver.Zero(t)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--username", "USER",
				"--password", "PASS",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
		assertCredentialPluginWriter(t, &stdout, server.LastTokenResponse().IDToken, tokenExpiryFuture)
	})

	t.Run("HasValidToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		preexist := tokencache.Value{
			IDToken: jwt.EncodeF(t, func(claims *jwt.Claims) {
				claims.Issuer = server.IssuerURL()
				claims.Subject = "SUBJECT"
				claims.Audience = []string{"kubernetes"}
				claims.IssuedAt = tokenExpiryFuture.Add(-time.Hour).Unix()
				claims.ExpiresAt = tokenExpiryFuture.Unix()
			}),
			RefreshToken: "VALID_REFRESH_TOKEN",
		}
		browserMock := httpdriver.Zero(t)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		setupTokenCache(t, tc, server.IssuerURL(), preexist)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), preexist)
		assertCredentialPluginWriter(t, &stdout, preexist.IDToken, tokenExpiryFuture)
	})

	t.Run("HasValidRefreshToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			RefreshToken:      "VALID_REFRESH_TOKEN",
		})
		defer server.Shutdown(t, ctx)
		preexist := tokencache.Value{
			IDToken: jwt.EncodeF(t, func(claims *jwt.Claims) {
				claims.Issuer = server.IssuerURL()
				claims.Subject = "SUBJECT"
				claims.Audience = []string{"kubernetes"}
				claims.IssuedAt = tokenExpiryPast.Add(-time.Hour).Unix()
				claims.ExpiresAt = tokenExpiryPast.Unix()
			}),
			RefreshToken: "VALID_REFRESH_TOKEN",
		}
		setupTokenCache(t, tc, server.IssuerURL(), preexist)
		browserMock := httpdriver.Zero(t)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
		assertCredentialPluginWriter(t, &stdout, server.LastTokenResponse().IDToken, tokenExpiryFuture)
	})

	t.Run("HasExpiredRefreshToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			RefreshError:      "token has expired",
			Scope:             "openid",
			RedirectURIPrefix: "http://localhost:",
			RefreshToken:      "EXPIRED_REFRESH_TOKEN",
		})
		defer server.Shutdown(t, ctx)
		preexist := tokencache.Value{
			IDToken: jwt.EncodeF(t, func(claims *jwt.Claims) {
				claims.Issuer = server.IssuerURL()
				claims.Subject = "SUBJECT"
				claims.Audience = []string{"kubernetes"}
				claims.IssuedAt = tokenExpiryPast.Add(-time.Hour).Unix()
				claims.ExpiresAt = tokenExpiryPast.Unix()
			}),
			RefreshToken: "EXPIRED_REFRESH_TOKEN",
		}
		setupTokenCache(t, tc, server.IssuerURL(), preexist)
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
			}, tc.extraArgs...))
		assertTokenCache(t, tc, server.IssuerURL(), tokencache.Value{
			IDToken:      server.LastTokenResponse().IDToken,
			RefreshToken: server.LastTokenResponse().RefreshToken,
		})
		assertCredentialPluginWriter(t, &stdout, server.LastTokenResponse().IDToken, tokenExpiryFuture)
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "email profile openid",
			RedirectURIPrefix: "http://localhost:",
		})
		defer server.Shutdown(t, ctx)
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--oidc-extra-scope", "email",
				"--oidc-extra-scope", "profile",
			}, tc.extraArgs...))
		assertCredentialPluginWriter(t, &stdout, server.LastTokenResponse().IDToken, tokenExpiryFuture)
	})

	t.Run("RedirectURLHostname", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		server := oidcserver.New(t, oidcserver.Config{
			TLS:               tc.idpTLS,
			IDTokenExpiry:     tokenExpiryFuture,
			Scope:             "openid",
			RedirectURIPrefix: "http://127.0.0.1:",
		})
		defer server.Shutdown(t, ctx)
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--oidc-redirect-url-hostname", "127.0.0.1",
			}, tc.extraArgs...))
		assertCredentialPluginWriter(t, &stdout, server.LastTokenResponse().IDToken, tokenExpiryFuture)
	})

	t.Run("ExtraParams", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
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
		browserMock := httpdriver.New(ctx, t, tc.idpTLS.TLSConfig)
		var stdout bytes.Buffer
		writerMock := credentialpluginwriter.NewTo(&stdout)
		runGetTokenCmd(t, ctx, browserMock, writerMock,
			append([]string{
				"--oidc-issuer-url", server.IssuerURL(),
				"--oidc-client-id", "kubernetes",
				"--oidc-auth-request-extra-params", "ttl=86400",
				"--oidc-auth-request-extra-params", "reauth=false",
			}, tc.extraArgs...))
		assertCredentialPluginWriter(t, &stdout, server.LastTokenResponse().IDToken, tokenExpiryFuture)
	})
}

func assertCredentialPluginWriter(t *testing.T, stdout io.Reader, token string, expiry time.Time) {
	var got clientauthenticationv1beta1.ExecCredential
	if err := json.NewDecoder(stdout).Decode(&got); err != nil {
		t.Errorf("could not decode json of the credential plugin: %s", err)
		return
	}
	want := clientauthenticationv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthenticationv1beta1.ExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: &metav1.Time{Time: expiry},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("kubeconfig mismatch (-want +got):\n%s", diff)
	}
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
