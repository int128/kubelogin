package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/integration_test/httpdriver"
	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/oidcserver"
	"github.com/int128/kubelogin/integration_test/oidcserver/testconfig"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/testing/clock"
	"github.com/int128/kubelogin/pkg/testing/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// Run the integration tests of the credential plugin use-case.
//
// 1. Start the auth server.
// 2. Run the Cmd.
// 3. Open a request for the local server.
// 4. Verify the output.
func TestCredentialPlugin(t *testing.T) {
	timeout := 10 * time.Second
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	tokenCacheDir := t.TempDir()

	for name, tc := range map[string]struct {
		keyPair keypair.KeyPair
		args    []string
	}{
		"NoTLS": {},
		"TLS": {
			keyPair: keypair.Server,
			args:    []string{"--certificate-authority", keypair.Server.CACertPath},
		},
	} {
		httpDriverConfig := httpdriver.Config{
			TLSConfig:    tc.keyPair.TLSConfig,
			BodyContains: "Authenticated",
		}

		t.Run(name, func(t *testing.T) {
			t.Run("AuthCode", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.TODO(), timeout)
				defer cancel()
				svc := oidcserver.New(t, tc.keyPair, testconfig.Config{
					Want: testconfig.Want{
						Scope:               "openid",
						RedirectURIPrefix:   "http://localhost:",
						CodeChallengeMethod: "S256",
					},
					Response: testconfig.Response{
						IDTokenExpiry:                 now.Add(time.Hour),
						CodeChallengeMethodsSupported: []string{"plain", "S256"},
					},
				})
				var stdout bytes.Buffer
				runGetToken(t, ctx, getTokenConfig{
					tokenCacheDir: tokenCacheDir,
					issuerURL:     svc.IssuerURL(),
					httpDriver:    httpdriver.New(ctx, t, httpDriverConfig),
					now:           now,
					stdout:        &stdout,
					args:          tc.args,
				})
				assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
			})

			t.Run("ROPC", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.TODO(), timeout)
				defer cancel()
				svc := oidcserver.New(t, tc.keyPair, testconfig.Config{
					Want: testconfig.Want{
						Scope:             "openid",
						RedirectURIPrefix: "http://localhost:",
						Username:          "USER1",
						Password:          "PASS1",
					},
					Response: testconfig.Response{
						IDTokenExpiry:                 now.Add(time.Hour),
						CodeChallengeMethodsSupported: []string{"plain", "S256"},
					},
				})
				var stdout bytes.Buffer
				runGetToken(t, ctx, getTokenConfig{
					tokenCacheDir: tokenCacheDir,
					issuerURL:     svc.IssuerURL(),
					httpDriver:    httpdriver.Zero(t),
					now:           now,
					stdout:        &stdout,
					args: append([]string{
						"--username", "USER1",
						"--password", "PASS1",
					}, tc.args...),
				})
				assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
			})

			t.Run("TokenCacheLifecycle", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.TODO(), timeout)
				defer cancel()
				svc := oidcserver.New(t, tc.keyPair, testconfig.Config{})

				t.Run("NoCache", func(t *testing.T) {
					svc.SetConfig(testconfig.Config{
						Want: testconfig.Want{
							Scope:               "openid",
							RedirectURIPrefix:   "http://localhost:",
							CodeChallengeMethod: "S256",
						},
						Response: testconfig.Response{
							IDTokenExpiry:                 now.Add(time.Hour),
							RefreshToken:                  "REFRESH_TOKEN_1",
							CodeChallengeMethodsSupported: []string{"plain", "S256"},
						},
					})
					var stdout bytes.Buffer
					runGetToken(t, ctx, getTokenConfig{
						tokenCacheDir: tokenCacheDir,
						issuerURL:     svc.IssuerURL(),
						httpDriver:    httpdriver.New(ctx, t, httpDriverConfig),
						now:           now,
						stdout:        &stdout,
						args:          tc.args,
					})
					assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
				})
				t.Run("Valid", func(t *testing.T) {
					svc.SetConfig(testconfig.Config{})
					var stdout bytes.Buffer
					runGetToken(t, ctx, getTokenConfig{
						tokenCacheDir: tokenCacheDir,
						issuerURL:     svc.IssuerURL(),
						httpDriver:    httpdriver.Zero(t),
						now:           now,
						stdout:        &stdout,
						args:          tc.args,
					})
					assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
				})
				t.Run("Refresh", func(t *testing.T) {
					svc.SetConfig(testconfig.Config{
						Want: testconfig.Want{
							Scope:             "openid",
							RedirectURIPrefix: "http://localhost:",
							RefreshToken:      "REFRESH_TOKEN_1",
						},
						Response: testconfig.Response{
							IDTokenExpiry:                 now.Add(3 * time.Hour),
							RefreshToken:                  "REFRESH_TOKEN_2",
							CodeChallengeMethodsSupported: []string{"plain", "S256"},
						},
					})
					var stdout bytes.Buffer
					runGetToken(t, ctx, getTokenConfig{
						tokenCacheDir: tokenCacheDir,
						issuerURL:     svc.IssuerURL(),
						httpDriver:    httpdriver.New(ctx, t, httpDriverConfig),
						now:           now.Add(2 * time.Hour),
						stdout:        &stdout,
						args:          tc.args,
					})
					assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(3*time.Hour))
				})
				t.Run("RefreshAgain", func(t *testing.T) {
					svc.SetConfig(testconfig.Config{
						Want: testconfig.Want{
							Scope:             "openid",
							RedirectURIPrefix: "http://localhost:",
							RefreshToken:      "REFRESH_TOKEN_2",
						},
						Response: testconfig.Response{
							IDTokenExpiry:                 now.Add(5 * time.Hour),
							CodeChallengeMethodsSupported: []string{"plain", "S256"},
						},
					})
					var stdout bytes.Buffer
					runGetToken(t, ctx, getTokenConfig{
						tokenCacheDir: tokenCacheDir,
						issuerURL:     svc.IssuerURL(),
						httpDriver:    httpdriver.New(ctx, t, httpDriverConfig),
						now:           now.Add(4 * time.Hour),
						stdout:        &stdout,
						args:          tc.args,
					})
					assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(5*time.Hour))
				})
			})
		})
	}

	t.Run("PKCE", func(t *testing.T) {
		t.Run("Not supported by provider", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			svc := oidcserver.New(t, keypair.None, testconfig.Config{
				Want: testconfig.Want{
					Scope:               "openid",
					RedirectURIPrefix:   "http://localhost:",
					CodeChallengeMethod: "",
				},
				Response: testconfig.Response{
					IDTokenExpiry:                 now.Add(time.Hour),
					CodeChallengeMethodsSupported: nil,
				},
			})
			var stdout bytes.Buffer
			runGetToken(t, ctx, getTokenConfig{
				tokenCacheDir: tokenCacheDir,
				issuerURL:     svc.IssuerURL(),
				httpDriver:    httpdriver.New(ctx, t, httpdriver.Config{BodyContains: "Authenticated"}),
				now:           now,
				stdout:        &stdout,
			})
			assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
		})

		t.Run("Enforce", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			svc := oidcserver.New(t, keypair.None, testconfig.Config{
				Want: testconfig.Want{
					Scope:               "openid",
					RedirectURIPrefix:   "http://localhost:",
					CodeChallengeMethod: "S256",
				},
				Response: testconfig.Response{
					IDTokenExpiry:                 now.Add(time.Hour),
					CodeChallengeMethodsSupported: nil,
				},
			})
			var stdout bytes.Buffer
			runGetToken(t, ctx, getTokenConfig{
				tokenCacheDir: tokenCacheDir,
				issuerURL:     svc.IssuerURL(),
				httpDriver:    httpdriver.New(ctx, t, httpdriver.Config{BodyContains: "Authenticated"}),
				now:           now,
				stdout:        &stdout,
				args:          []string{"--oidc-use-pkce"},
			})
			assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
		})
	})

	t.Run("TLSData", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		svc := oidcserver.New(t, keypair.Server, testconfig.Config{
			Want: testconfig.Want{
				Scope:               "openid",
				RedirectURIPrefix:   "http://localhost:",
				CodeChallengeMethod: "S256",
			},
			Response: testconfig.Response{
				IDTokenExpiry:                 now.Add(time.Hour),
				CodeChallengeMethodsSupported: []string{"plain", "S256"},
			},
		})
		var stdout bytes.Buffer
		runGetToken(t, ctx, getTokenConfig{
			tokenCacheDir: tokenCacheDir,
			issuerURL:     svc.IssuerURL(),
			httpDriver:    httpdriver.New(ctx, t, httpdriver.Config{TLSConfig: keypair.Server.TLSConfig, BodyContains: "Authenticated"}),
			now:           now,
			stdout:        &stdout,
			args:          []string{"--certificate-authority-data", keypair.Server.CACertBase64},
		})
		assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		svc := oidcserver.New(t, keypair.None, testconfig.Config{
			Want: testconfig.Want{
				Scope:               "email profile openid",
				RedirectURIPrefix:   "http://localhost:",
				CodeChallengeMethod: "S256",
			},
			Response: testconfig.Response{
				IDTokenExpiry:                 now.Add(time.Hour),
				CodeChallengeMethodsSupported: []string{"plain", "S256"},
			},
		})
		var stdout bytes.Buffer
		runGetToken(t, ctx, getTokenConfig{
			tokenCacheDir: tokenCacheDir,
			issuerURL:     svc.IssuerURL(),
			httpDriver:    httpdriver.New(ctx, t, httpdriver.Config{BodyContains: "Authenticated"}),
			now:           now,
			stdout:        &stdout,
			args: []string{
				"--oidc-extra-scope", "email",
				"--oidc-extra-scope", "profile",
			},
		})
		assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
	})

	t.Run("OpenURLAfterAuthentication", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		svc := oidcserver.New(t, keypair.None, testconfig.Config{
			Want: testconfig.Want{
				Scope:               "openid",
				RedirectURIPrefix:   "http://localhost:",
				CodeChallengeMethod: "S256",
			},
			Response: testconfig.Response{
				IDTokenExpiry:                 now.Add(time.Hour),
				CodeChallengeMethodsSupported: []string{"plain", "S256"},
			},
		})
		var stdout bytes.Buffer
		runGetToken(t, ctx, getTokenConfig{
			tokenCacheDir: tokenCacheDir,
			issuerURL:     svc.IssuerURL(),
			httpDriver:    httpdriver.New(ctx, t, httpdriver.Config{BodyContains: "URL=https://example.com/success"}),
			now:           now,
			stdout:        &stdout,
			args:          []string{"--open-url-after-authentication", "https://example.com/success"},
		})
		assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
	})

	t.Run("RedirectURLHostname", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		svc := oidcserver.New(t, keypair.None, testconfig.Config{
			Want: testconfig.Want{
				Scope:               "openid",
				RedirectURIPrefix:   "http://127.0.0.1:",
				CodeChallengeMethod: "S256",
			},
			Response: testconfig.Response{
				IDTokenExpiry:                 now.Add(time.Hour),
				CodeChallengeMethodsSupported: []string{"plain", "S256"},
			},
		})
		var stdout bytes.Buffer
		runGetToken(t, ctx, getTokenConfig{
			tokenCacheDir: tokenCacheDir,
			issuerURL:     svc.IssuerURL(),
			httpDriver:    httpdriver.New(ctx, t, httpdriver.Config{BodyContains: "Authenticated"}),
			now:           now,
			stdout:        &stdout,
			args:          []string{"--oidc-redirect-url-hostname", "127.0.0.1"},
		})
		assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
	})

	t.Run("RedirectURLHTTPS", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		svc := oidcserver.New(t, keypair.None, testconfig.Config{
			Want: testconfig.Want{
				Scope:               "openid",
				RedirectURIPrefix:   "https://localhost:",
				CodeChallengeMethod: "S256",
			},
			Response: testconfig.Response{
				IDTokenExpiry:                 now.Add(time.Hour),
				CodeChallengeMethodsSupported: []string{"plain", "S256"},
			},
		})
		var stdout bytes.Buffer
		runGetToken(t, ctx, getTokenConfig{
			tokenCacheDir: tokenCacheDir,
			issuerURL:     svc.IssuerURL(),
			httpDriver: httpdriver.New(ctx, t, httpdriver.Config{
				TLSConfig:    keypair.Server.TLSConfig,
				BodyContains: "Authenticated",
			}),
			now:    now,
			stdout: &stdout,
			args: []string{
				"--local-server-cert", keypair.Server.CertPath,
				"--local-server-key", keypair.Server.KeyPath,
			},
		})
		assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
	})

	t.Run("ExtraParams", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		svc := oidcserver.New(t, keypair.None, testconfig.Config{
			Want: testconfig.Want{
				Scope:               "openid",
				RedirectURIPrefix:   "http://localhost:",
				CodeChallengeMethod: "S256",
				ExtraParams: map[string]string{
					"ttl":    "86400",
					"reauth": "false",
				},
			},
			Response: testconfig.Response{
				IDTokenExpiry:                 now.Add(time.Hour),
				CodeChallengeMethodsSupported: []string{"plain", "S256"},
			},
		})
		var stdout bytes.Buffer
		runGetToken(t, ctx, getTokenConfig{
			tokenCacheDir: tokenCacheDir,
			issuerURL:     svc.IssuerURL(),
			httpDriver:    httpdriver.New(ctx, t, httpdriver.Config{BodyContains: "Authenticated"}),
			now:           now,
			stdout:        &stdout,
			args: []string{
				"--oidc-auth-request-extra-params", "ttl=86400",
				"--oidc-auth-request-extra-params", "reauth=false",
			},
		})
		assertCredentialPluginStdout(t, &stdout, svc.LastTokenResponse().IDToken, now.Add(time.Hour))
	})
}

type getTokenConfig struct {
	tokenCacheDir string
	issuerURL     string
	httpDriver    browser.Interface
	stdout        io.Writer
	now           time.Time
	args          []string
}

func runGetToken(t *testing.T, ctx context.Context, cfg getTokenConfig) {
	cmd := di.NewCmdForHeadless(clock.Fake(cfg.now), os.Stdin, cfg.stdout, logger.New(t), cfg.httpDriver)
	t.Setenv(
		"KUBERNETES_EXEC_INFO",
		`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1","spec":{"interactive":true}}`,
	)
	exitCode := cmd.Run(ctx, append([]string{
		"kubelogin",
		"get-token",
		"--token-cache-dir", cfg.tokenCacheDir,
		"--oidc-issuer-url", cfg.issuerURL,
		"--oidc-client-id", "kubernetes",
		"--listen-address", "127.0.0.1:0",
	}, cfg.args...), "latest")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}

func assertCredentialPluginStdout(t *testing.T, stdout io.Reader, token string, expiry time.Time) {
	var got clientauthenticationv1.ExecCredential
	if err := json.NewDecoder(stdout).Decode(&got); err != nil {
		t.Errorf("could not decode json of the credential plugin: %s", err)
		return
	}
	want := clientauthenticationv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthenticationv1.ExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: &metav1.Time{Time: expiry},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("stdout mismatch (-want +got):\n%s", diff)
	}
}
