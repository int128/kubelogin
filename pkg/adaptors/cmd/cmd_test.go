package cmd

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin/mock_credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
	"github.com/int128/kubelogin/pkg/usecases/standalone/mock_standalone"
)

func TestCmd_Run(t *testing.T) {
	const executable = "kubelogin"
	const version = "HEAD"

	t.Run("login/Defaults", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		mockStandalone := mock_standalone.NewMockInterface(ctrl)
		mockStandalone.EXPECT().
			Do(ctx, standalone.Input{
				AuthCodeOption: &authentication.AuthCodeOption{
					BindAddress: []string{"127.0.0.1:8000", "127.0.0.1:18000"},
				},
			})
		cmd := Cmd{
			Root: &Root{
				Standalone: mockStandalone,
				Logger:     mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("login/AuthCodeOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		mockStandalone := mock_standalone.NewMockInterface(ctrl)
		mockStandalone.EXPECT().
			Do(ctx, standalone.Input{
				AuthCodeOption: &authentication.AuthCodeOption{
					BindAddress:     []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					SkipOpenBrowser: true,
				},
			})
		cmd := Cmd{
			Root: &Root{
				Standalone: mockStandalone,
				Logger:     mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"--listen-port", "10080",
			"--listen-port", "20080",
			"--skip-open-browser",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("login/FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		mockStandalone := mock_standalone.NewMockInterface(ctrl)
		mockStandalone.EXPECT().
			Do(ctx, standalone.Input{
				KubeconfigFilename: "/path/to/kubeconfig",
				KubeconfigContext:  "hello.k8s.local",
				KubeconfigUser:     "google",
				CACertFilename:     "/path/to/cacert",
				SkipTLSVerify:      true,
				ROPCOption: &authentication.ROPCOption{
					Username: "USER",
					Password: "PASS",
				},
			})
		cmd := Cmd{
			Root: &Root{
				Standalone: mockStandalone,
				Logger:     mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"--kubeconfig", "/path/to/kubeconfig",
			"--context", "hello.k8s.local",
			"--user", "google",
			"--certificate-authority", "/path/to/cacert",
			"--insecure-skip-tls-verify",
			"-v1",
			"--listen-port", "10080",
			"--listen-port", "20080",
			"--skip-open-browser",
			"--username", "USER",
			"--password", "PASS",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("login/TooManyArgs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cmd := Cmd{
			Root: &Root{
				Standalone: mock_standalone.NewMockInterface(ctrl),
				Logger:     mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(context.TODO(), []string{executable, "some"}, version)
		if exitCode != 1 {
			t.Errorf("exitCode wants 1 but %d", exitCode)
		}
	})

	t.Run("get-token/Defaults", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		getToken := mock_credentialplugin.NewMockInterface(ctrl)
		getToken.EXPECT().
			Do(ctx, credentialplugin.Input{
				TokenCacheDir: defaultTokenCacheDir,
				IssuerURL:     "https://issuer.example.com",
				ClientID:      "YOUR_CLIENT_ID",
				AuthCodeOption: &authentication.AuthCodeOption{
					BindAddress: []string{"127.0.0.1:8000", "127.0.0.1:18000"},
				},
			})
		cmd := Cmd{
			Root: &Root{
				Logger: mock_logger.New(t),
			},
			GetToken: &GetToken{
				GetToken: getToken,
				Logger:   mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"get-token",
			"--oidc-issuer-url", "https://issuer.example.com",
			"--oidc-client-id", "YOUR_CLIENT_ID",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("get-token/AuthCodeOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		getToken := mock_credentialplugin.NewMockInterface(ctrl)
		getToken.EXPECT().
			Do(ctx, credentialplugin.Input{
				TokenCacheDir: defaultTokenCacheDir,
				IssuerURL:     "https://issuer.example.com",
				ClientID:      "YOUR_CLIENT_ID",
				AuthCodeOption: &authentication.AuthCodeOption{
					BindAddress:     []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					SkipOpenBrowser: true,
				},
			})
		cmd := Cmd{
			Root: &Root{
				Logger: mock_logger.New(t),
			},
			GetToken: &GetToken{
				GetToken: getToken,
				Logger:   mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"get-token",
			"--oidc-issuer-url", "https://issuer.example.com",
			"--oidc-client-id", "YOUR_CLIENT_ID",
			"--listen-port", "10080",
			"--listen-port", "20080",
			"--skip-open-browser",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("get-token/FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		getToken := mock_credentialplugin.NewMockInterface(ctrl)
		getToken.EXPECT().
			Do(ctx, credentialplugin.Input{
				TokenCacheDir:  defaultTokenCacheDir,
				IssuerURL:      "https://issuer.example.com",
				ClientID:       "YOUR_CLIENT_ID",
				ClientSecret:   "YOUR_CLIENT_SECRET",
				ExtraScopes:    []string{"email", "profile"},
				CACertFilename: "/path/to/cacert",
				SkipTLSVerify:  true,
				ROPCOption: &authentication.ROPCOption{
					Username: "USER",
					Password: "PASS",
				},
			})
		cmd := Cmd{
			Root: &Root{
				Logger: mock_logger.New(t),
			},
			GetToken: &GetToken{
				GetToken: getToken,
				Logger:   mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"get-token",
			"--oidc-issuer-url", "https://issuer.example.com",
			"--oidc-client-id", "YOUR_CLIENT_ID",
			"--oidc-client-secret", "YOUR_CLIENT_SECRET",
			"--oidc-extra-scope", "email",
			"--oidc-extra-scope", "profile",
			"--certificate-authority", "/path/to/cacert",
			"--insecure-skip-tls-verify",
			"-v1",
			"--listen-port", "10080",
			"--listen-port", "20080",
			"--skip-open-browser",
			"--username", "USER",
			"--password", "PASS",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("get-token/MissingMandatoryOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		cmd := Cmd{
			Root: &Root{
				Logger: mock_logger.New(t),
			},
			GetToken: &GetToken{
				GetToken: mock_credentialplugin.NewMockInterface(ctrl),
				Logger:   mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable, "get-token"}, version)
		if exitCode != 1 {
			t.Errorf("exitCode wants 1 but %d", exitCode)
		}
	})

	t.Run("get-token/TooManyArgs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		cmd := Cmd{
			Root: &Root{
				Logger: mock_logger.New(t),
			},
			GetToken: &GetToken{
				GetToken: mock_credentialplugin.NewMockInterface(ctrl),
				Logger:   mock_logger.New(t),
			},
			Logger: mock_logger.New(t),
		}
		exitCode := cmd.Run(ctx, []string{executable, "get-token", "foo"}, version)
		if exitCode != 1 {
			t.Errorf("exitCode wants 1 but %d", exitCode)
		}
	})
}
