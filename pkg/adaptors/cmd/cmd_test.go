package cmd

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors"
	"github.com/int128/kubelogin/pkg/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/pkg/usecases"
	"github.com/int128/kubelogin/pkg/usecases/mock_usecases"
)

func TestCmd_Run(t *testing.T) {
	const executable = "kubelogin"
	const version = "HEAD"

	t.Run("login/Defaults", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		login := mock_usecases.NewMockLogin(ctrl)
		login.EXPECT().
			Do(ctx, usecases.LoginIn{
				ListenPort: defaultListenPort,
			})

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().SetLevel(adaptors.LogLevel(0))

		cmd := Cmd{
			Login:  login,
			Logger: logger,
		}
		exitCode := cmd.Run(ctx, []string{executable}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("login/FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		login := mock_usecases.NewMockLogin(ctrl)
		login.EXPECT().
			Do(ctx, usecases.LoginIn{
				KubeconfigFilename: "/path/to/kubeconfig",
				KubeconfigContext:  "hello.k8s.local",
				KubeconfigUser:     "google",
				CACertFilename:     "/path/to/cacert",
				SkipTLSVerify:      true,
				ListenPort:         []int{10080, 20080},
				SkipOpenBrowser:    true,
				Username:           "USER",
				Password:           "PASS",
			})

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().SetLevel(adaptors.LogLevel(1))

		cmd := Cmd{
			Login:  login,
			Logger: logger,
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
			Login:  mock_usecases.NewMockLogin(ctrl),
			Logger: mock_adaptors.NewLogger(t, ctrl),
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

		getToken := mock_usecases.NewMockGetToken(ctrl)
		getToken.EXPECT().
			Do(ctx, usecases.GetTokenIn{
				ListenPort:    defaultListenPort,
				TokenCacheDir: defaultTokenCacheDir,
				IssuerURL:     "https://issuer.example.com",
				ClientID:      "YOUR_CLIENT_ID",
			})

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().SetLevel(adaptors.LogLevel(0))

		cmd := Cmd{
			GetToken: getToken,
			Logger:   logger,
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

	t.Run("get-token/FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		getToken := mock_usecases.NewMockGetToken(ctrl)
		getToken.EXPECT().
			Do(ctx, usecases.GetTokenIn{
				TokenCacheDir:   defaultTokenCacheDir,
				IssuerURL:       "https://issuer.example.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{"email", "profile"},
				CACertFilename:  "/path/to/cacert",
				SkipTLSVerify:   true,
				ListenPort:      []int{10080, 20080},
				SkipOpenBrowser: true,
				Username:        "USER",
				Password:        "PASS",
			})

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().SetLevel(adaptors.LogLevel(1))

		cmd := Cmd{
			GetToken: getToken,
			Logger:   logger,
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
			GetToken: mock_usecases.NewMockGetToken(ctrl),
			Logger:   mock_adaptors.NewLogger(t, ctrl),
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
			GetToken: mock_usecases.NewMockGetToken(ctrl),
			Logger:   mock_adaptors.NewLogger(t, ctrl),
		}
		exitCode := cmd.Run(ctx, []string{executable, "get-token", "foo"}, version)
		if exitCode != 1 {
			t.Errorf("exitCode wants 1 but %d", exitCode)
		}
	})
}
