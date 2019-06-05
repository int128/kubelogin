package login

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/pkg/errors"
)

func TestExec_Do(t *testing.T) {
	t.Run("Defaults", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		auth := newAuth("", "")

		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(auth, nil)
		mockKubeconfig.EXPECT().
			UpdateAuth(newAuth("YOUR_ID_TOKEN", "YOUR_REFRESH_TOKEN"))

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(adaptors.OIDCClientConfig{Config: auth.OIDCConfig}).
			Return(newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
				Config:          auth.OIDCConfig,
				LocalServerPort: []int{10000},
			}), nil)

		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().
			Exec(ctx, "kubectl", []string{"foo", "bar"}).
			Return(0, nil)

		u := Exec{
			Kubeconfig: mockKubeconfig,
			OIDC:       mockOIDC,
			Env:        mockEnv,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, usecases.LoginAndExecIn{
			LoginIn: usecases.LoginIn{
				ListenPort: []int{10000},
			},
			Executable: "kubectl",
			Args:       []string{"foo", "bar"},
		})
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		if out.ExitCode != 0 {
			t.Errorf("ExitCode wants 0 but %d", out.ExitCode)
		}
	})

	t.Run("NoOIDCConfig", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(nil, errors.New("no oidc config"))

		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().
			Exec(ctx, "kubectl", []string{"foo", "bar"}).
			Return(0, nil)

		u := Exec{
			Kubeconfig: mockKubeconfig,
			OIDC:       mock_adaptors.NewMockOIDC(ctrl),
			Env:        mockEnv,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, usecases.LoginAndExecIn{
			LoginIn: usecases.LoginIn{
				ListenPort: []int{10000},
			},
			Executable: "kubectl",
			Args:       []string{"foo", "bar"},
		})
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		if out.ExitCode != 0 {
			t.Errorf("ExitCode wants 0 but %d", out.ExitCode)
		}
	})
}
