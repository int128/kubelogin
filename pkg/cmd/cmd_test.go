package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/usecases/credentialplugin_mock"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/usecases/setup_mock"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/usecases/standalone_mock"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/setup"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
)

func TestCmd_Run(t *testing.T) {
	const executable = "kubelogin"
	const version = "HEAD"

	defaultGrantOptionSet := authentication.GrantOptionSet{
		AuthCodeBrowserOption: &authcode.BrowserOption{
			BindAddress:           defaultListenAddress,
			AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
			RedirectURLHostname:   "localhost",
		},
	}

	t.Run("root", func(t *testing.T) {
		tests := map[string]struct {
			args []string
			in   standalone.Input
		}{
			"Defaults": {
				args: []string{executable},
				in: standalone.Input{
					GrantOptionSet: defaultGrantOptionSet,
				},
			},
			"FullOptions": {
				args: []string{executable,
					"--kubeconfig", "/path/to/kubeconfig",
					"--context", "hello.k8s.local",
					"--user", "google",
					"-v1",
				},
				in: standalone.Input{
					KubeconfigFilename: "/path/to/kubeconfig",
					KubeconfigContext:  "hello.k8s.local",
					KubeconfigUser:     "google",
					GrantOptionSet:     defaultGrantOptionSet,
				},
			},
		}
		for name, c := range tests {
			t.Run(name, func(t *testing.T) {
				ctx := context.TODO()
				mockStandalone := standalone_mock.NewMockInterface(t)
				mockStandalone.EXPECT().
					Do(ctx, c.in).
					Return(nil)
				cmd := Cmd{
					Root: &Root{
						Standalone: mockStandalone,
						Logger:     logger.New(t),
					},
					Logger: logger.New(t),
				}
				exitCode := cmd.Run(ctx, c.args, version)
				if exitCode != 0 {
					t.Errorf("exitCode wants 0 but %d", exitCode)
				}
			})
		}

		t.Run("TooManyArgs", func(t *testing.T) {
			cmd := Cmd{
				Root: &Root{
					Standalone: standalone_mock.NewMockInterface(t),
					Logger:     logger.New(t),
				},
				Logger: logger.New(t),
			}
			exitCode := cmd.Run(context.TODO(), []string{executable, "some"}, version)
			if exitCode != 1 {
				t.Errorf("exitCode wants 1 but %d", exitCode)
			}
		})
	})

	t.Run("get-token", func(t *testing.T) {
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("os.UserHomeDir error: %s", err)
		}

		tests := map[string]struct {
			args []string
			in   credentialplugin.Input
		}{
			"Defaults": {
				args: []string{executable,
					"get-token",
					"--oidc-issuer-url", "https://issuer.example.com",
					"--oidc-client-id", "YOUR_CLIENT_ID",
				},
				in: credentialplugin.Input{
					Provider: oidc.Provider{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "YOUR_CLIENT_ID",
					},
					TokenCacheConfig: tokencache.Config{
						Directory: filepath.Join(userHomeDir, ".kube/cache/oidc-login"),
						Storage:   tokencache.StorageAuto,
					},
					GrantOptionSet: defaultGrantOptionSet,
				},
			},
			"FullOptions": {
				args: []string{executable,
					"get-token",
					"--oidc-issuer-url", "https://issuer.example.com",
					"--oidc-client-id", "YOUR_CLIENT_ID",
					"--oidc-client-secret", "YOUR_CLIENT_SECRET",
					"--oidc-extra-scope", "email",
					"--oidc-extra-scope", "profile",
					"--token-cache-storage", "disk",
					"-v1",
				},
				in: credentialplugin.Input{
					Provider: oidc.Provider{
						IssuerURL:    "https://issuer.example.com",
						ClientID:     "YOUR_CLIENT_ID",
						ClientSecret: "YOUR_CLIENT_SECRET",
						ExtraScopes:  []string{"email", "profile"},
					},
					TokenCacheConfig: tokencache.Config{
						Directory: filepath.Join(userHomeDir, ".kube/cache/oidc-login"),
						Storage:   tokencache.StorageDisk,
					},
					GrantOptionSet: defaultGrantOptionSet,
				},
			},
			"AccessToken": {
				args: []string{executable,
					"get-token",
					"--oidc-issuer-url", "https://issuer.example.com",
					"--oidc-client-id", "YOUR_CLIENT_ID",
					"--oidc-use-access-token=true",
				},
				in: credentialplugin.Input{
					Provider: oidc.Provider{
						IssuerURL:      "https://issuer.example.com",
						ClientID:       "YOUR_CLIENT_ID",
						UseAccessToken: true,
					},
					TokenCacheConfig: tokencache.Config{
						Directory: filepath.Join(userHomeDir, ".kube/cache/oidc-login"),
						Storage:   tokencache.StorageAuto,
					},
					GrantOptionSet: defaultGrantOptionSet,
				},
			},
			"HomedirExpansion": {
				args: []string{executable,
					"get-token",
					"--oidc-issuer-url", "https://issuer.example.com",
					"--oidc-client-id", "YOUR_CLIENT_ID",
					"--certificate-authority", "~/.kube/ca.crt",
					"--local-server-cert", "~/.kube/oidc-server.crt",
					"--local-server-key", "~/.kube/oidc-server.key",
					"--token-cache-dir", "~/.kube/oidc-cache",
				},
				in: credentialplugin.Input{
					Provider: oidc.Provider{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "YOUR_CLIENT_ID",
					},
					TokenCacheConfig: tokencache.Config{
						Directory: filepath.Join(userHomeDir, ".kube/oidc-cache"),
						Storage:   tokencache.StorageAuto,
					},
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeBrowserOption: &authcode.BrowserOption{
							BindAddress:           defaultListenAddress,
							AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
							RedirectURLHostname:   "localhost",
							LocalServerCertFile:   filepath.Join(userHomeDir, ".kube/oidc-server.crt"),
							LocalServerKeyFile:    filepath.Join(userHomeDir, ".kube/oidc-server.key"),
						},
					},
					TLSClientConfig: tlsclientconfig.Config{
						CACertFilename: []string{filepath.Join(userHomeDir, ".kube/ca.crt")},
					},
				},
			},
		}
		for name, c := range tests {
			t.Run(name, func(t *testing.T) {
				ctx := context.TODO()
				getToken := credentialplugin_mock.NewMockInterface(t)
				getToken.EXPECT().
					Do(ctx, c.in).
					Return(nil)
				cmd := Cmd{
					Root: &Root{
						Logger: logger.New(t),
					},
					GetToken: &GetToken{
						GetToken: getToken,
						Logger:   logger.New(t),
					},
					Logger: logger.New(t),
				}
				exitCode := cmd.Run(ctx, c.args, version)
				if exitCode != 0 {
					t.Errorf("exitCode wants 0 but %d", exitCode)
				}
			})
		}

		t.Run("MissingMandatoryOptions", func(t *testing.T) {
			ctx := context.TODO()
			cmd := Cmd{
				Root: &Root{
					Logger: logger.New(t),
				},
				GetToken: &GetToken{
					GetToken: credentialplugin_mock.NewMockInterface(t),
					Logger:   logger.New(t),
				},
				Logger: logger.New(t),
			}
			exitCode := cmd.Run(ctx, []string{executable, "get-token"}, version)
			if exitCode != 1 {
				t.Errorf("exitCode wants 1 but %d", exitCode)
			}
		})

		t.Run("TooManyArgs", func(t *testing.T) {
			ctx := context.TODO()
			cmd := Cmd{
				Root: &Root{
					Logger: logger.New(t),
				},
				GetToken: &GetToken{
					GetToken: credentialplugin_mock.NewMockInterface(t),
					Logger:   logger.New(t),
				},
				Logger: logger.New(t),
			}
			exitCode := cmd.Run(ctx, []string{executable, "get-token", "foo"}, version)
			if exitCode != 1 {
				t.Errorf("exitCode wants 1 but %d", exitCode)
			}
		})
	})

	t.Run("setup", func(t *testing.T) {
		t.Run("NoOption", func(t *testing.T) {
			ctx := context.TODO()
			cmd := Cmd{
				Logger: logger.New(t),
				Root: &Root{
					Logger: logger.New(t),
				},
			}
			exitCode := cmd.Run(ctx, []string{executable, "setup"}, version)
			if exitCode != 0 {
				t.Errorf("exitCode wants 0 but %d", exitCode)
			}
		})

		t.Run("WithOptions", func(t *testing.T) {
			ctx := context.TODO()
			setupMock := setup_mock.NewMockInterface(t)
			setupMock.EXPECT().Do(ctx, setup.Input{
				IssuerURL:      "https://issuer.example.com",
				ClientID:       "YOUR_CLIENT",
				ExtraScopes:    []string{"email", "profile"},
				GrantOptionSet: defaultGrantOptionSet,
				ChangedFlags: []string{
					"--oidc-issuer-url=https://issuer.example.com",
					"--oidc-client-id=YOUR_CLIENT",
					"--oidc-extra-scope=email",
					"--oidc-extra-scope=profile",
				},
			}).Return(nil)
			cmd := Cmd{
				Logger: logger.New(t),
				Root: &Root{
					Logger: logger.New(t),
				},
				Setup: &Setup{
					Setup: setupMock,
				},
			}
			exitCode := cmd.Run(ctx, []string{executable, "setup",
				"--oidc-issuer-url", "https://issuer.example.com",
				"--oidc-client-id", "YOUR_CLIENT",
				"--oidc-extra-scope", "email,profile",
			}, version)
			if exitCode != 0 {
				t.Errorf("exitCode wants 0 but %d", exitCode)
			}
		})
	})
}
