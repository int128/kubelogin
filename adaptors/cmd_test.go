package adaptors

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/int128/kubelogin/usecases/mock_usecases"
)

func TestCmd_Run(t *testing.T) {
	const executable = "kubelogin"
	const version = "HEAD"

	t.Run("Defaults", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		login := mock_usecases.NewMockLogin(ctrl)
		login.EXPECT().
			Do(ctx, usecases.LoginIn{
				ListenPort: defaultListenPort,
			})

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().
			SetLevel(adaptors.LogLevel(0))

		cmd := Cmd{
			Login:  login,
			Logger: logger,
		}
		exitCode := cmd.Run(ctx, []string{executable}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		login := mock_usecases.NewMockLogin(ctrl)
		login.EXPECT().
			Do(ctx, usecases.LoginIn{
				KubeConfigFilename:           "/path/to/kubeconfig",
				KubeContextName:              "hello.k8s.local",
				KubeUserName:                 "google",
				CertificateAuthorityFilename: "/path/to/cacert",
				SkipTLSVerify:                true,
				ListenPort:                   []int{10080, 20080},
				SkipOpenBrowser:              true,
				Username:                     "USER",
				Password:                     "PASS",
			})

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().
			SetLevel(adaptors.LogLevel(1))

		cmd := Cmd{
			Login:  login,
			Logger: logger,
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"--kubeconfig", "/path/to/kubeconfig",
			"--context", "hello.k8s.local",
			"--user", "google",
			"--listen-port", "10080",
			"--listen-port", "20080",
			"--skip-open-browser",
			"--certificate-authority", "/path/to/cacert",
			"--insecure-skip-tls-verify",
			"--username", "USER",
			"--password", "PASS",
			"-v1",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("TooManyArgs", func(t *testing.T) {
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
}

func TestCmd_executableName(t *testing.T) {
	t.Run("kubelogin", func(t *testing.T) {
		e := executableName("kubelogin")
		if e != "kubelogin" {
			t.Errorf("executableName wants kubelogin but %s", e)
		}
	})
	t.Run("kubectl-oidc_login", func(t *testing.T) {
		e := executableName("kubectl-oidc_login")
		if e != "kubectl oidc-login" {
			t.Errorf("executableName wants kubectl oidc-login but %s", e)
		}
	})
}
