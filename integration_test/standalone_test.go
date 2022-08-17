package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/int128/kubelogin/integration_test/httpdriver"
	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/kubeconfig"
	"github.com/int128/kubelogin/integration_test/oidcserver"
	"github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/testing/clock"
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
	timeout := 3 * time.Second
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	for name, tc := range map[string]struct {
		keyPair keypair.KeyPair
		args    []string
	}{
		"NoTLS": {},
		"TLS": {
			keyPair: keypair.Server,
		},
	} {
		httpDriverOption := httpdriver.Option{
			TLSConfig:    tc.keyPair.TLSConfig,
			BodyContains: "Authenticated",
		}

		t.Run(name, func(t *testing.T) {
			t.Run("AuthCode", func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.TODO(), timeout)
				defer cancel()
				sv := oidcserver.New(t, tc.keyPair, oidcserver.Config{
					Want: oidcserver.Want{
						Scope:             "openid",
						RedirectURIPrefix: "http://localhost:",
					},
					Response: oidcserver.Response{
						IDTokenExpiry: now.Add(time.Hour),
					},
				})
				kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
					Issuer:                  sv.IssuerURL(),
					IDPCertificateAuthority: tc.keyPair.CACertPath,
				})
				runStandalone(t, ctx, standaloneConfig{
					issuerURL:          sv.IssuerURL(),
					kubeConfigFilename: kubeConfigFilename,
					httpDriver:         httpdriver.New(ctx, t, httpDriverOption),
					now:                now,
				})
				kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
					IDToken:      sv.LastTokenResponse().IDToken,
					RefreshToken: sv.LastTokenResponse().RefreshToken,
				})
			})

			t.Run("ROPC", func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.TODO(), timeout)
				defer cancel()
				sv := oidcserver.New(t, tc.keyPair, oidcserver.Config{
					Want: oidcserver.Want{
						Scope:             "openid",
						RedirectURIPrefix: "http://localhost:",
						Username:          "USER1",
						Password:          "PASS1",
					},
					Response: oidcserver.Response{
						IDTokenExpiry: now.Add(time.Hour),
					},
				})
				kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
					Issuer:                  sv.IssuerURL(),
					IDPCertificateAuthority: tc.keyPair.CACertPath,
				})
				runStandalone(t, ctx, standaloneConfig{
					issuerURL:          sv.IssuerURL(),
					kubeConfigFilename: kubeConfigFilename,
					httpDriver:         httpdriver.Zero(t),
					now:                now,
					args: []string{
						"--username", "USER1",
						"--password", "PASS1",
					},
				})
				kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
					IDToken:      sv.LastTokenResponse().IDToken,
					RefreshToken: sv.LastTokenResponse().RefreshToken,
				})
			})

			t.Run("TokenLifecycle", func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.TODO(), timeout)
				defer cancel()
				sv := oidcserver.New(t, tc.keyPair, oidcserver.Config{})
				kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
					Issuer:                  sv.IssuerURL(),
					IDPCertificateAuthority: tc.keyPair.CACertPath,
				})

				t.Run("NoToken", func(t *testing.T) {
					sv.SetConfig(oidcserver.Config{
						Want: oidcserver.Want{
							Scope:             "openid",
							RedirectURIPrefix: "http://localhost:",
						},
						Response: oidcserver.Response{
							IDTokenExpiry: now.Add(time.Hour),
							RefreshToken:  "REFRESH_TOKEN_1",
						},
					})
					runStandalone(t, ctx, standaloneConfig{
						issuerURL:          sv.IssuerURL(),
						kubeConfigFilename: kubeConfigFilename,
						httpDriver:         httpdriver.New(ctx, t, httpDriverOption),
						now:                now,
					})
					kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
						IDToken:      sv.LastTokenResponse().IDToken,
						RefreshToken: "REFRESH_TOKEN_1",
					})
				})
				t.Run("Valid", func(t *testing.T) {
					sv.SetConfig(oidcserver.Config{})
					runStandalone(t, ctx, standaloneConfig{
						issuerURL:          sv.IssuerURL(),
						kubeConfigFilename: kubeConfigFilename,
						httpDriver:         httpdriver.Zero(t),
						now:                now,
					})
					kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
						IDToken:      sv.LastTokenResponse().IDToken,
						RefreshToken: "REFRESH_TOKEN_1",
					})
				})
				t.Run("Refresh", func(t *testing.T) {
					sv.SetConfig(oidcserver.Config{
						Want: oidcserver.Want{
							Scope:             "openid",
							RedirectURIPrefix: "http://localhost:",
							RefreshToken:      "REFRESH_TOKEN_1",
						},
						Response: oidcserver.Response{
							IDTokenExpiry: now.Add(3 * time.Hour),
							RefreshToken:  "REFRESH_TOKEN_2",
						},
					})
					runStandalone(t, ctx, standaloneConfig{
						issuerURL:          sv.IssuerURL(),
						kubeConfigFilename: kubeConfigFilename,
						httpDriver:         httpdriver.New(ctx, t, httpDriverOption),
						now:                now.Add(2 * time.Hour),
					})
					kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
						IDToken:      sv.LastTokenResponse().IDToken,
						RefreshToken: "REFRESH_TOKEN_2",
					})
				})
				t.Run("RefreshAgain", func(t *testing.T) {
					sv.SetConfig(oidcserver.Config{
						Want: oidcserver.Want{
							Scope:             "openid",
							RedirectURIPrefix: "http://localhost:",
							RefreshToken:      "REFRESH_TOKEN_2",
						},
						Response: oidcserver.Response{
							IDTokenExpiry: now.Add(5 * time.Hour),
						},
					})
					runStandalone(t, ctx, standaloneConfig{
						issuerURL:          sv.IssuerURL(),
						kubeConfigFilename: kubeConfigFilename,
						httpDriver:         httpdriver.New(ctx, t, httpDriverOption),
						now:                now.Add(4 * time.Hour),
					})
					kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
						IDToken:      sv.LastTokenResponse().IDToken,
						RefreshToken: "REFRESH_TOKEN_2",
					})
				})
			})
		})
	}

	t.Run("TLSData", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		sv := oidcserver.New(t, keypair.Server, oidcserver.Config{
			Want: oidcserver.Want{
				Scope:             "openid",
				RedirectURIPrefix: "http://localhost:",
			},
			Response: oidcserver.Response{
				IDTokenExpiry: now.Add(time.Hour),
			},
		})
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                      sv.IssuerURL(),
			IDPCertificateAuthorityData: keypair.Server.CACertBase64,
		})
		runStandalone(t, ctx, standaloneConfig{
			issuerURL:          sv.IssuerURL(),
			kubeConfigFilename: kubeConfigFilename,
			httpDriver:         httpdriver.New(ctx, t, httpdriver.Option{TLSConfig: keypair.Server.TLSConfig}),
			now:                now,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      sv.LastTokenResponse().IDToken,
			RefreshToken: sv.LastTokenResponse().RefreshToken,
		})
	})

	t.Run("env_KUBECONFIG", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		sv := oidcserver.New(t, keypair.None, oidcserver.Config{
			Want: oidcserver.Want{
				Scope:             "openid",
				RedirectURIPrefix: "http://localhost:",
			},
			Response: oidcserver.Response{
				IDTokenExpiry: now.Add(time.Hour),
			},
		})
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer: sv.IssuerURL(),
		})
		t.Setenv("KUBECONFIG", kubeConfigFilename+string(os.PathListSeparator)+"kubeconfig/testdata/dummy.yaml")
		runStandalone(t, ctx, standaloneConfig{
			issuerURL:  sv.IssuerURL(),
			httpDriver: httpdriver.New(ctx, t, httpdriver.Option{}),
			now:        now,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      sv.LastTokenResponse().IDToken,
			RefreshToken: sv.LastTokenResponse().RefreshToken,
		})
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		sv := oidcserver.New(t, keypair.None, oidcserver.Config{
			Want: oidcserver.Want{
				Scope:             "profile groups openid",
				RedirectURIPrefix: "http://localhost:",
			},
			Response: oidcserver.Response{
				IDTokenExpiry: now.Add(time.Hour),
			},
		})
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:      sv.IssuerURL(),
			ExtraScopes: "profile,groups",
		})
		runStandalone(t, ctx, standaloneConfig{
			issuerURL:          sv.IssuerURL(),
			kubeConfigFilename: kubeConfigFilename,
			httpDriver:         httpdriver.New(ctx, t, httpdriver.Option{}),
			now:                now,
		})
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      sv.LastTokenResponse().IDToken,
			RefreshToken: sv.LastTokenResponse().RefreshToken,
		})
	})
}

type standaloneConfig struct {
	issuerURL          string
	kubeConfigFilename string
	httpDriver         browser.Interface
	now                time.Time
	args               []string
}

func runStandalone(t *testing.T, ctx context.Context, cfg standaloneConfig) {
	cmd := di.NewCmdForHeadless(clock.Fake(cfg.now), os.Stdin, os.Stdout, logger.New(t), cfg.httpDriver)
	exitCode := cmd.Run(ctx, append([]string{
		"kubelogin",
		"--kubeconfig", cfg.kubeConfigFilename,
		"--listen-address", "127.0.0.1:0",
	}, cfg.args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}
