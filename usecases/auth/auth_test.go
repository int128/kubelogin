package auth

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/models/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"golang.org/x/xerrors"
)

func TestAuthentication_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	pastTime := time.Now().Add(-time.Hour)  //TODO: inject time service
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service

	t.Run("AuthorizationCodeFlow", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.AuthenticationIn{
			ListenPort:      []int{10000},
			SkipOpenBrowser: true,
			CACertFilename:  "/path/to/cert",
			SkipTLSVerify:   true,
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByCode(ctx, adaptors.OIDCAuthenticateByCodeIn{
				LocalServerPort: []int{10000},
				SkipOpenBrowser: true,
			}).
			Return(&adaptors.OIDCAuthenticateOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(ctx, adaptors.OIDCClientConfig{
				Config:         in.OIDCConfig,
				CACertFilename: "/path/to/cert",
				SkipTLSVerify:  true,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDC:   mockOIDC,
			Logger: mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.AuthenticationOut{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenExpiry: futureTime,
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("ResourceOwnerPasswordCredentialsFlow/UsePassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.AuthenticationIn{
			Username:       "USER",
			Password:       "PASS",
			CACertFilename: "/path/to/cert",
			SkipTLSVerify:  true,
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByPassword(ctx, adaptors.OIDCAuthenticateByPasswordIn{
				Username: "USER",
				Password: "PASS",
			}).
			Return(&adaptors.OIDCAuthenticateOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(ctx, adaptors.OIDCClientConfig{
				Config:         in.OIDCConfig,
				CACertFilename: "/path/to/cert",
				SkipTLSVerify:  true,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDC:   mockOIDC,
			Logger: mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.AuthenticationOut{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenExpiry: futureTime,
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("ResourceOwnerPasswordCredentialsFlow/AskPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.AuthenticationIn{
			Username: "USER",
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByPassword(ctx, adaptors.OIDCAuthenticateByPasswordIn{
				Username: "USER",
				Password: "PASS",
			}).
			Return(&adaptors.OIDCAuthenticateOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(ctx, adaptors.OIDCClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mockOIDCClient, nil)
		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)
		u := Authentication{
			OIDC:   mockOIDC,
			Env:    mockEnv,
			Logger: mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.AuthenticationOut{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenExpiry: futureTime,
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("ResourceOwnerPasswordCredentialsFlow/AskPasswordError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.AuthenticationIn{
			Username: "USER",
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(ctx, adaptors.OIDCClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mock_adaptors.NewMockOIDCClient(ctrl), nil)
		mockEnv := mock_adaptors.NewMockEnv(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("", xerrors.New("error"))
		u := Authentication{
			OIDC:   mockOIDC,
			Env:    mockEnv,
			Logger: mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.AuthenticationIn{
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				IDToken:      "VALID_ID_TOKEN",
			},
		}
		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			Verify(ctx, adaptors.OIDCVerifyIn{IDToken: "VALID_ID_TOKEN"}).
			Return(&adaptors.OIDCVerifyOut{
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(ctx, adaptors.OIDCClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDC:   mockOIDC,
			Logger: mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.AuthenticationOut{
			AlreadyHasValidIDToken: true,
			IDToken:                "VALID_ID_TOKEN",
			IDTokenExpiry:          futureTime,
			IDTokenClaims:          dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("HasValidRefreshToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.AuthenticationIn{
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				IDToken:      "EXPIRED_ID_TOKEN",
				RefreshToken: "VALID_REFRESH_TOKEN",
			},
		}
		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			Verify(ctx, adaptors.OIDCVerifyIn{IDToken: "EXPIRED_ID_TOKEN"}).
			Return(&adaptors.OIDCVerifyOut{
				IDTokenExpiry: pastTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCClient.EXPECT().
			Refresh(ctx, adaptors.OIDCRefreshIn{
				RefreshToken: "VALID_REFRESH_TOKEN",
			}).
			Return(&adaptors.OIDCAuthenticateOut{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(ctx, adaptors.OIDCClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDC:   mockOIDC,
			Logger: mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.AuthenticationOut{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenExpiry: futureTime,
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("HasExpiredRefreshToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.AuthenticationIn{
			ListenPort: []int{10000},
			OIDCConfig: kubeconfig.OIDCConfig{
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				IDToken:      "EXPIRED_ID_TOKEN",
				RefreshToken: "EXPIRED_REFRESH_TOKEN",
			},
		}
		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			Verify(ctx, adaptors.OIDCVerifyIn{IDToken: "EXPIRED_ID_TOKEN"}).
			Return(&adaptors.OIDCVerifyOut{
				IDTokenExpiry: pastTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCClient.EXPECT().
			Refresh(ctx, adaptors.OIDCRefreshIn{
				RefreshToken: "EXPIRED_REFRESH_TOKEN",
			}).
			Return(nil, xerrors.New("token has expired"))
		mockOIDCClient.EXPECT().
			AuthenticateByCode(ctx, adaptors.OIDCAuthenticateByCodeIn{
				LocalServerPort: []int{10000},
			}).
			Return(&adaptors.OIDCAuthenticateOut{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			New(ctx, adaptors.OIDCClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDC:   mockOIDC,
			Logger: mock_adaptors.NewLogger(t, ctrl),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &usecases.AuthenticationOut{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenExpiry: futureTime,
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})
}
