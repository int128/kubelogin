package login

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/int128/kubelogin/usecases/mock_usecases"
	"golang.org/x/xerrors"
)

func TestExec_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service

	t.Run("FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginAndExecIn{
			Executable: "kubectl",
			Args:       []string{"foo", "bar"},
			LoginIn: usecases.LoginIn{
				KubeconfigFilename: "/path/to/kubeconfig",
				KubeconfigContext:  "theContext",
				KubeconfigUser:     "theUser",
				ListenPort:         []int{10000},
				SkipOpenBrowser:    true,
				Username:           "USER",
				Password:           "PASS",
				CACertFilename:     "/path/to/cert",
				SkipTLSVerify:      true,
			},
		}
		currentAuth := &kubeconfig.Auth{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "google",
			OIDCConfig: kubeconfig.OIDCConfig{
				IDPIssuerURL: "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("/path/to/kubeconfig", kubeconfig.ContextName("theContext"), kubeconfig.UserName("theUser")).
			Return(currentAuth, nil)
		mockKubeconfig.EXPECT().
			UpdateAuth(&kubeconfig.Auth{
				LocationOfOrigin: "/path/to/kubeconfig",
				UserName:         "google",
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					IDToken:      "YOUR_ID_TOKEN",
					RefreshToken: "YOUR_REFRESH_TOKEN",
				},
			})
		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().
			Exec(ctx, "kubectl", []string{"foo", "bar"}).
			Return(123, nil)
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{
				CurrentAuth:     currentAuth,
				ListenPort:      []int{10000},
				SkipOpenBrowser: true,
				Username:        "USER",
				Password:        "PASS",
				CACertFilename:  "/path/to/cert",
				SkipTLSVerify:   true,
			}).
			Return(&usecases.AuthenticationOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Exec{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Env:            mockEnv,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.LoginAndExecOut{
			ExitCode: 123,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginAndExecIn{
			Executable: "kubectl",
			Args:       []string{"foo", "bar"},
		}
		currentAuth := &kubeconfig.Auth{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "theUser",
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				IDToken:      "VALID_ID_TOKEN",
			},
		}
		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().
			Exec(ctx, "kubectl", []string{"foo", "bar"}).
			Return(0, nil)
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuth, nil)
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{CurrentAuth: currentAuth}).
			Return(&usecases.AuthenticationOut{
				AlreadyHasValidIDToken: true,
				IDToken:                "VALID_ID_TOKEN",
				IDTokenExpiry:          futureTime,
				IDTokenClaims:          dummyTokenClaims,
			}, nil)
		u := Exec{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Env:            mockEnv,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.LoginAndExecOut{
			ExitCode: 0,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("NoOIDCConfig", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginAndExecIn{
			Executable: "kubectl",
			Args:       []string{"foo", "bar"},
			LoginIn:    usecases.LoginIn{},
		}
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(nil, xerrors.New("no oidc config"))
		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().
			Exec(ctx, "kubectl", []string{"foo", "bar"}).
			Return(0, nil)
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		u := Exec{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Env:            mockEnv,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.LoginAndExecOut{
			ExitCode: 0,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginAndExecIn{}
		currentAuth := &kubeconfig.Auth{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "google",
			OIDCConfig: kubeconfig.OIDCConfig{
				IDPIssuerURL: "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuth, nil)
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{CurrentAuth: currentAuth}).
			Return(nil, xerrors.New("authentication error"))
		u := Exec{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Env:            mock_adaptors.NewMockEnv(ctrl),
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})

	t.Run("WriteError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginAndExecIn{}
		currentAuth := &kubeconfig.Auth{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "google",
			OIDCConfig: kubeconfig.OIDCConfig{
				IDPIssuerURL: "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuth, nil)
		mockKubeconfig.EXPECT().
			UpdateAuth(&kubeconfig.Auth{
				LocationOfOrigin: "/path/to/kubeconfig",
				UserName:         "google",
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					IDToken:      "YOUR_ID_TOKEN",
					RefreshToken: "YOUR_REFRESH_TOKEN",
				},
			}).
			Return(xerrors.New("I/O error"))
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{CurrentAuth: currentAuth}).
			Return(&usecases.AuthenticationOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Exec{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Env:            mock_adaptors.NewMockEnv(ctrl),
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})
}
