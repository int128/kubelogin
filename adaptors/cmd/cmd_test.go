package cmd

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/usecases"
	"github.com/int128/kubelogin/usecases/mock_usecases"
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

	t.Run("loginAndExec/Defaults", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		loginAndExec := mock_usecases.NewMockLoginAndExec(ctrl)
		loginAndExec.EXPECT().
			Do(ctx, usecases.LoginAndExecIn{
				LoginIn: usecases.LoginIn{
					ListenPort: defaultListenPort,
				},
				Executable: "kubectl",
				Args:       []string{"dummy"},
			}).
			Return(&usecases.LoginAndExecOut{ExitCode: 0}, nil)

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().SetLevel(adaptors.LogLevel(0))

		cmd := Cmd{
			LoginAndExec: loginAndExec,
			Logger:       logger,
		}
		exitCode := cmd.Run(ctx, []string{executable, "exec", "--", "kubectl", "dummy"}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("loginAndExec/OptionsInExtraArgs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		loginAndExec := mock_usecases.NewMockLoginAndExec(ctrl)
		loginAndExec.EXPECT().
			Do(ctx, usecases.LoginAndExecIn{
				LoginIn: usecases.LoginIn{
					KubeconfigFilename: "/path/to/kubeconfig2",
					KubeconfigContext:  "hello2.k8s.local",
					KubeconfigUser:     "google2",
					CACertFilename:     "/path/to/cacert2",
					SkipTLSVerify:      true,
					ListenPort:         defaultListenPort,
				},
				Executable: "kubectl",
				Args: []string{
					"--kubeconfig", "/path/to/kubeconfig2",
					"--context", "hello2.k8s.local",
					"--user", "google2",
					"--certificate-authority", "/path/to/cacert2",
					"--insecure-skip-tls-verify",
					"-v2",
					"--listen-port", "30080",
					"--skip-open-browser",
					"--username", "USER2",
					"--password", "PASS2",
					"dummy",
					"--dummy",
					"--help",
				},
			}).
			Return(&usecases.LoginAndExecOut{ExitCode: 0}, nil)

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().SetLevel(adaptors.LogLevel(2))

		cmd := Cmd{
			LoginAndExec: loginAndExec,
			Logger:       logger,
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"exec",
			"--",
			"kubectl",
			// kubectl options in the extra args should be mapped to the options
			"--kubeconfig", "/path/to/kubeconfig2",
			"--context", "hello2.k8s.local",
			"--user", "google2",
			"--certificate-authority", "/path/to/cacert2",
			"--insecure-skip-tls-verify",
			"-v2",
			// kubelogin options in the extra args should not affect
			"--listen-port", "30080",
			"--skip-open-browser",
			"--username", "USER2",
			"--password", "PASS2",
			"dummy",
			"--dummy",
			"--help",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("loginAndExec/OverrideOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		loginAndExec := mock_usecases.NewMockLoginAndExec(ctrl)
		loginAndExec.EXPECT().
			Do(ctx, usecases.LoginAndExecIn{
				LoginIn: usecases.LoginIn{
					KubeconfigFilename: "/path/to/kubeconfig2",
					KubeconfigContext:  "hello2.k8s.local",
					KubeconfigUser:     "google2",
					CACertFilename:     "/path/to/cacert2",
					SkipTLSVerify:      true,
					ListenPort:         []int{10080, 20080},
					SkipOpenBrowser:    true,
					Username:           "USER",
					Password:           "PASS",
				},
				Executable: "kubectl",
				Args: []string{
					"--kubeconfig", "/path/to/kubeconfig2",
					"--context", "hello2.k8s.local",
					"--user", "google2",
					"--certificate-authority", "/path/to/cacert2",
					"--insecure-skip-tls-verify",
					"-v2",
					"--listen-port", "30080",
					"--skip-open-browser",
					"--username", "USER2",
					"--password", "PASS2",
					"dummy",
					"--dummy",
				},
			}).
			Return(&usecases.LoginAndExecOut{ExitCode: 0}, nil)

		logger := mock_adaptors.NewLogger(t, ctrl)
		logger.EXPECT().SetLevel(adaptors.LogLevel(2))

		cmd := Cmd{
			LoginAndExec: loginAndExec,
			Logger:       logger,
		}
		exitCode := cmd.Run(ctx, []string{executable,
			// kubelogin options in the first args should be mapped to the options
			"--listen-port", "10080",
			"--listen-port", "20080",
			"--skip-open-browser",
			"--username", "USER",
			"--password", "PASS",
			"exec",
			"--",
			"kubectl",
			// kubectl options in the extra args should be mapped to the options
			"--kubeconfig", "/path/to/kubeconfig2",
			"--context", "hello2.k8s.local",
			"--user", "google2",
			"--certificate-authority", "/path/to/cacert2",
			"--insecure-skip-tls-verify",
			"-v2",
			// kubelogin options in the extra args should not affect
			"--listen-port", "30080",
			"--skip-open-browser",
			"--username", "USER2",
			"--password", "PASS2",
			"dummy",
			"--dummy",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})
}
