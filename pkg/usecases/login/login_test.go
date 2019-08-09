package login

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/pkg/models/kubeconfig"
	"github.com/int128/kubelogin/pkg/usecases"
	"github.com/int128/kubelogin/pkg/usecases/mock_usecases"
	"golang.org/x/xerrors"
)

func TestLogin_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service

	t.Run("FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginIn{
			KubeconfigFilename: "/path/to/kubeconfig",
			KubeconfigContext:  "theContext",
			KubeconfigUser:     "theUser",
			ListenPort:         []int{10000},
			SkipOpenBrowser:    true,
			Username:           "USER",
			Password:           "PASS",
			CACertFilename:     "/path/to/cert",
			SkipTLSVerify:      true,
		}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "theUser",
			OIDCConfig: kubeconfig.OIDCConfig{
				IDPIssuerURL: "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("/path/to/kubeconfig", kubeconfig.ContextName("theContext"), kubeconfig.UserName("theUser")).
			Return(currentAuthProvider, nil)
		mockKubeconfig.EXPECT().
			UpdateAuthProvider(&kubeconfig.AuthProvider{
				LocationOfOrigin: "/path/to/kubeconfig",
				UserName:         "theUser",
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					IDToken:      "YOUR_ID_TOKEN",
					RefreshToken: "YOUR_REFRESH_TOKEN",
				},
			})
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{
				OIDCConfig:      currentAuthProvider.OIDCConfig,
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
		u := Login{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginIn{}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "theUser",
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				IDToken:      "VALID_ID_TOKEN",
			},
		}
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{OIDCConfig: currentAuthProvider.OIDCConfig}).
			Return(&usecases.AuthenticationOut{
				AlreadyHasValidIDToken: true,
				IDToken:                "VALID_ID_TOKEN",
				IDTokenExpiry:          futureTime,
				IDTokenClaims:          dummyTokenClaims,
			}, nil)
		u := Login{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("NoOIDCConfig", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginIn{}
		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(nil, xerrors.New("no oidc config"))
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		u := Login{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginIn{}
		currentAuthProvider := &kubeconfig.AuthProvider{
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
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{OIDCConfig: currentAuthProvider.OIDCConfig}).
			Return(nil, xerrors.New("authentication error"))
		u := Login{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("WriteError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.LoginIn{}
		currentAuthProvider := &kubeconfig.AuthProvider{
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
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockKubeconfig.EXPECT().
			UpdateAuthProvider(&kubeconfig.AuthProvider{
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
			Do(ctx, usecases.AuthenticationIn{OIDCConfig: currentAuthProvider.OIDCConfig}).
			Return(&usecases.AuthenticationOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Login{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Logger:         mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
