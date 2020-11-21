package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin/mock_credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
	"github.com/int128/kubelogin/pkg/usecases/standalone/mock_standalone"
)

func TestCmd_Run(t *testing.T) {
	const executable = "kubelogin"
	const version = "HEAD"

	t.Run("root", func(t *testing.T) {
		tests := map[string]struct {
			args []string
			in   standalone.Input
		}{
			"Defaults": {
				args: []string{executable},
				in: standalone.Input{
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeBrowserOption: &authcode.BrowserOption{
							BindAddress:           defaultListenAddress,
							AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
							RedirectURLHostname:   "localhost",
						},
					},
				},
			},
			"when --listen-port is set, it should convert the port to address": {
				args: []string{
					executable,
					"--listen-port", "10080",
					"--listen-port", "20080",
				},
				in: standalone.Input{
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeBrowserOption: &authcode.BrowserOption{
							BindAddress:           []string{"127.0.0.1:10080", "127.0.0.1:20080"},
							AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
							RedirectURLHostname:   "localhost",
						},
					},
				},
			},
			"when --listen-port is set, it should ignore --listen-address flags": {
				args: []string{
					executable,
					"--listen-port", "10080",
					"--listen-port", "20080",
					"--listen-address", "127.0.0.1:30080",
					"--listen-address", "127.0.0.1:40080",
				},
				in: standalone.Input{
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeBrowserOption: &authcode.BrowserOption{
							BindAddress:           []string{"127.0.0.1:10080", "127.0.0.1:20080"},
							AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
							RedirectURLHostname:   "localhost",
						},
					},
				},
			},
			"FullOptions": {
				args: []string{executable,
					"--kubeconfig", "/path/to/kubeconfig",
					"--context", "hello.k8s.local",
					"--user", "google",
					"--certificate-authority", "/path/to/cacert",
					"--certificate-authority-data", "BASE64ENCODED",
					"--insecure-skip-tls-verify",
					"-v1",
					"--grant-type", "authcode",
					"--listen-address", "127.0.0.1:10080",
					"--listen-address", "127.0.0.1:20080",
					"--skip-open-browser",
					"--authentication-timeout-sec", "10",
					"--local-server-cert", "/path/to/local-server-cert",
					"--local-server-key", "/path/to/local-server-key",
					"--open-url-after-authentication", "https://example.com/success.html",
					"--username", "USER",
					"--password", "PASS",
				},
				in: standalone.Input{
					KubeconfigFilename: "/path/to/kubeconfig",
					KubeconfigContext:  "hello.k8s.local",
					KubeconfigUser:     "google",
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeBrowserOption: &authcode.BrowserOption{
							BindAddress:                []string{"127.0.0.1:10080", "127.0.0.1:20080"},
							SkipOpenBrowser:            true,
							AuthenticationTimeout:      10 * time.Second,
							LocalServerCertFile:        "/path/to/local-server-cert",
							LocalServerKeyFile:         "/path/to/local-server-key",
							OpenURLAfterAuthentication: "https://example.com/success.html",
							RedirectURLHostname:        "localhost",
						},
					},
					TLSClientConfig: tlsclientconfig.Config{
						CACertFilename: []string{"/path/to/cacert"},
						CACertData:     []string{"BASE64ENCODED"},
						SkipTLSVerify:  true,
					},
				},
			},
			"GrantType=authcode-keyboard": {
				args: []string{executable,
					"--grant-type", "authcode-keyboard",
				},
				in: standalone.Input{
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeKeyboardOption: &authcode.KeyboardOption{},
					},
				},
			},
			"GrantType=password": {
				args: []string{executable,
					"--grant-type", "password",
					"--listen-address", "127.0.0.1:10080",
					"--listen-address", "127.0.0.1:20080",
					"--username", "USER",
					"--password", "PASS",
				},
				in: standalone.Input{
					GrantOptionSet: authentication.GrantOptionSet{
						ROPCOption: &ropc.Option{
							Username: "USER",
							Password: "PASS",
						},
					},
				},
			},
			"GrantType=auto": {
				args: []string{executable,
					"--listen-address", "127.0.0.1:10080",
					"--listen-address", "127.0.0.1:20080",
					"--username", "USER",
					"--password", "PASS",
				},
				in: standalone.Input{
					GrantOptionSet: authentication.GrantOptionSet{
						ROPCOption: &ropc.Option{
							Username: "USER",
							Password: "PASS",
						},
					},
				},
			},
		}
		for name, c := range tests {
			t.Run(name, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				ctx := context.TODO()
				mockStandalone := mock_standalone.NewMockInterface(ctrl)
				mockStandalone.EXPECT().
					Do(ctx, c.in)
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
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			cmd := Cmd{
				Root: &Root{
					Standalone: mock_standalone.NewMockInterface(ctrl),
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
					TokenCacheDir: defaultTokenCacheDir,
					Provider: oidc.Provider{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "YOUR_CLIENT_ID",
					},
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeBrowserOption: &authcode.BrowserOption{
							BindAddress:           []string{"127.0.0.1:8000", "127.0.0.1:18000"},
							AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
							RedirectURLHostname:   "localhost",
						},
					},
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
					"--certificate-authority", "/path/to/cacert",
					"--certificate-authority-data", "BASE64ENCODED",
					"--insecure-skip-tls-verify",
					"-v1",
					"--grant-type", "authcode",
					"--listen-address", "127.0.0.1:10080",
					"--listen-address", "127.0.0.1:20080",
					"--skip-open-browser",
					"--authentication-timeout-sec", "10",
					"--local-server-cert", "/path/to/local-server-cert",
					"--local-server-key", "/path/to/local-server-key",
					"--open-url-after-authentication", "https://example.com/success.html",
					"--oidc-auth-request-extra-params", "ttl=86400",
					"--oidc-auth-request-extra-params", "reauth=true",
					"--username", "USER",
					"--password", "PASS",
				},
				in: credentialplugin.Input{
					TokenCacheDir: defaultTokenCacheDir,
					Provider: oidc.Provider{
						IssuerURL:    "https://issuer.example.com",
						ClientID:     "YOUR_CLIENT_ID",
						ClientSecret: "YOUR_CLIENT_SECRET",
						ExtraScopes:  []string{"email", "profile"},
					},
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeBrowserOption: &authcode.BrowserOption{
							BindAddress:                []string{"127.0.0.1:10080", "127.0.0.1:20080"},
							SkipOpenBrowser:            true,
							AuthenticationTimeout:      10 * time.Second,
							LocalServerCertFile:        "/path/to/local-server-cert",
							LocalServerKeyFile:         "/path/to/local-server-key",
							OpenURLAfterAuthentication: "https://example.com/success.html",
							RedirectURLHostname:        "localhost",
							AuthRequestExtraParams:     map[string]string{"ttl": "86400", "reauth": "true"},
						},
					},
					TLSClientConfig: tlsclientconfig.Config{
						CACertFilename: []string{"/path/to/cacert"},
						CACertData:     []string{"BASE64ENCODED"},
						SkipTLSVerify:  true,
					},
				},
			},
			"GrantType=authcode-keyboard": {
				args: []string{executable,
					"get-token",
					"--oidc-issuer-url", "https://issuer.example.com",
					"--oidc-client-id", "YOUR_CLIENT_ID",
					"--grant-type", "authcode-keyboard",
					"--oidc-auth-request-extra-params", "ttl=86400",
				},
				in: credentialplugin.Input{
					TokenCacheDir: defaultTokenCacheDir,
					Provider: oidc.Provider{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "YOUR_CLIENT_ID",
					},
					GrantOptionSet: authentication.GrantOptionSet{
						AuthCodeKeyboardOption: &authcode.KeyboardOption{
							AuthRequestExtraParams: map[string]string{"ttl": "86400"},
						},
					},
				},
			},
			"GrantType=password": {
				args: []string{executable,
					"get-token",
					"--oidc-issuer-url", "https://issuer.example.com",
					"--oidc-client-id", "YOUR_CLIENT_ID",
					"--grant-type", "password",
					"--listen-address", "127.0.0.1:10080",
					"--listen-address", "127.0.0.1:20080",
					"--username", "USER",
					"--password", "PASS",
				},
				in: credentialplugin.Input{
					TokenCacheDir: defaultTokenCacheDir,
					Provider: oidc.Provider{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "YOUR_CLIENT_ID",
					},
					GrantOptionSet: authentication.GrantOptionSet{
						ROPCOption: &ropc.Option{
							Username: "USER",
							Password: "PASS",
						},
					},
				},
			},
			"GrantType=auto": {
				args: []string{executable,
					"get-token",
					"--oidc-issuer-url", "https://issuer.example.com",
					"--oidc-client-id", "YOUR_CLIENT_ID",
					"--listen-address", "127.0.0.1:10080",
					"--listen-address", "127.0.0.1:20080",
					"--username", "USER",
					"--password", "PASS",
				},
				in: credentialplugin.Input{
					TokenCacheDir: defaultTokenCacheDir,
					Provider: oidc.Provider{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "YOUR_CLIENT_ID",
					},
					GrantOptionSet: authentication.GrantOptionSet{
						ROPCOption: &ropc.Option{
							Username: "USER",
							Password: "PASS",
						},
					},
				},
			},
		}
		for name, c := range tests {
			t.Run(name, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				ctx := context.TODO()
				getToken := mock_credentialplugin.NewMockInterface(ctrl)
				getToken.EXPECT().
					Do(ctx, c.in)
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
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.TODO()
			cmd := Cmd{
				Root: &Root{
					Logger: logger.New(t),
				},
				GetToken: &GetToken{
					GetToken: mock_credentialplugin.NewMockInterface(ctrl),
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
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.TODO()
			cmd := Cmd{
				Root: &Root{
					Logger: logger.New(t),
				},
				GetToken: &GetToken{
					GetToken: mock_credentialplugin.NewMockInterface(ctrl),
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
}
