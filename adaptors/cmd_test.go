package adaptors

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/int128/kubelogin/usecases/mock_usecases"
	"github.com/mitchellh/go-homedir"
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
				KubeConfig: expand(t, "~/.kube/config"),
				ListenPort: 8000,
			})

		cmd := Cmd{
			Login: login,
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
				KubeConfig:      expand(t, "~/.kube/config"),
				ListenPort:      10080,
				SkipTLSVerify:   true,
				SkipOpenBrowser: true,
			})

		cmd := Cmd{
			Login: login,
		}
		exitCode := cmd.Run(ctx, []string{executable,
			"--listen-port", "10080",
			"--insecure-skip-tls-verify",
			"--skip-open-browser",
		}, version)
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("TooManyArgs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cmd := Cmd{
			Login: mock_usecases.NewMockLogin(ctrl),
		}
		exitCode := cmd.Run(context.TODO(), []string{executable, "some"}, version)
		if exitCode != 1 {
			t.Errorf("exitCode wants 1 but %d", exitCode)
		}
	})
}

func expand(t *testing.T, path string) string {
	d, err := homedir.Expand(path)
	if err != nil {
		t.Fatalf("could not expand: %s", err)
	}
	return d
}
