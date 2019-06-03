package login

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/pkg/errors"
)

func newMockCodeOIDC(ctrl *gomock.Controller, ctx context.Context, in adaptors.OIDCAuthenticateByCodeIn) *mock_adaptors.MockOIDCClient {
	mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
	mockOIDCClient.EXPECT().
		AuthenticateByCode(ctx, in).
		Return(&adaptors.OIDCAuthenticateOut{
			VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
			IDToken:         "YOUR_ID_TOKEN",
			RefreshToken:    "YOUR_REFRESH_TOKEN",
		}, nil)
	return mockOIDCClient
}

func newMockPasswordOIDC(ctrl *gomock.Controller, ctx context.Context, in adaptors.OIDCAuthenticateByPasswordIn) *mock_adaptors.MockOIDCClient {
	mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
	mockOIDCClient.EXPECT().
		AuthenticateByPassword(ctx, in).
		Return(&adaptors.OIDCAuthenticateOut{
			VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
			IDToken:         "YOUR_ID_TOKEN",
			RefreshToken:    "YOUR_REFRESH_TOKEN",
		}, nil)
	return mockOIDCClient
}

func newAuth(idToken, refreshToken string) *kubeconfig.Auth {
	return &kubeconfig.Auth{
		LocationOfOrigin: "theLocation",
		UserName:         "google",
		OIDCConfig: kubeconfig.OIDCConfig{
			IDPIssuerURL: "https://accounts.google.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			IDToken:      idToken,
			RefreshToken: refreshToken,
		},
	}
}

func TestLogin_Do(t *testing.T) {
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

		u := Login{
			Kubeconfig: mockKubeconfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort: []int{10000},
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		auth := newAuth("", "")

		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("/path/to/kubeconfig", kubeconfig.ContextName("theContext"), kubeconfig.UserName("theUser")).
			Return(auth, nil)
		mockKubeconfig.EXPECT().
			UpdateAuth(newAuth("YOUR_ID_TOKEN", "YOUR_REFRESH_TOKEN"))

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(adaptors.OIDCClientConfig{
				Config:         auth.OIDCConfig,
				CACertFilename: "/path/to/cert",
				SkipTLSVerify:  true,
			}).
			Return(newMockPasswordOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByPasswordIn{
				Config:   auth.OIDCConfig,
				Username: "USER",
				Password: "PASS",
			}), nil)

		u := Login{
			Kubeconfig: mockKubeconfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeconfigFilename: "/path/to/kubeconfig",
			KubeconfigContext:  "theContext",
			KubeconfigUser:     "theUser",
			Username:           "USER",
			Password:           "PASS",
			CACertFilename:     "/path/to/cert",
			SkipTLSVerify:      true,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("AskPassword", func(t *testing.T) {
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
			Return(newMockPasswordOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByPasswordIn{
				Config:   auth.OIDCConfig,
				Username: "USER",
				Password: "PASS",
			}), nil)

		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)

		u := Login{
			Kubeconfig: mockKubeconfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Env:        mockEnv,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			Username: "USER",
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("AskPasswordError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		auth := newAuth("", "")

		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(auth, nil)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(adaptors.OIDCClientConfig{Config: auth.OIDCConfig}).
			Return(mock_adaptors.NewMockOIDCClient(ctrl), nil)

		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("", errors.New("error"))

		u := Login{
			Kubeconfig: mockKubeconfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Env:        mockEnv,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			Username: "USER",
		}); err == nil {
			t.Errorf("err wants an error but nil")
		}
	})

	t.Run("KubeconfigHasValidToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		auth := newAuth("VALID_ID_TOKEN", "N/A")

		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(auth, nil)

		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			Verify(ctx, adaptors.OIDCVerifyIn{Config: auth.OIDCConfig}).
			Return(&oidc.IDToken{Expiry: time.Now()}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(adaptors.OIDCClientConfig{Config: auth.OIDCConfig}).
			Return(mockOIDCClient, nil)

		u := Login{
			Kubeconfig: mockKubeconfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeconfigHasExpiredToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		auth := newAuth("EXPIRED_ID_TOKEN", "EXPIRED_REFRESH_TOKEN")

		mockKubeconfig := mock_adaptors.NewMockKubeconfig(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuth("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(auth, nil)
		mockKubeconfig.EXPECT().
			UpdateAuth(newAuth("YOUR_ID_TOKEN", "YOUR_REFRESH_TOKEN"))

		mockOIDCClient := newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{Config: auth.OIDCConfig})
		mockOIDCClient.EXPECT().
			Verify(ctx, adaptors.OIDCVerifyIn{Config: auth.OIDCConfig}).
			Return(nil, errors.New("token expired"))
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(adaptors.OIDCClientConfig{Config: auth.OIDCConfig}).
			Return(mockOIDCClient, nil)

		u := Login{
			Kubeconfig: mockKubeconfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})
}
