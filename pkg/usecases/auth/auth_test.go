package auth

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/env/mock_env"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidc"
	"github.com/int128/kubelogin/pkg/adaptors/oidc/mock_oidc"
	"github.com/int128/kubelogin/pkg/models/kubeconfig"
	"github.com/int128/kubelogin/pkg/usecases"
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
		mockOIDCClient := mock_oidc.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByCode(ctx, oidc.AuthenticateByCodeIn{
				LocalServerPort: []int{10000},
				SkipOpenBrowser: true,
			}).
			Return(&oidc.AuthenticateOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCFactory := mock_oidc.NewMockFactoryInterface(ctrl)
		mockOIDCFactory.EXPECT().
			New(ctx, oidc.ClientConfig{
				Config:         in.OIDCConfig,
				CACertFilename: "/path/to/cert",
				SkipTLSVerify:  true,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCFactory: mockOIDCFactory,
			Logger:      mock_logger.New(t),
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
		mockOIDCClient := mock_oidc.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByPassword(ctx, oidc.AuthenticateByPasswordIn{
				Username: "USER",
				Password: "PASS",
			}).
			Return(&oidc.AuthenticateOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCFactory := mock_oidc.NewMockFactoryInterface(ctrl)
		mockOIDCFactory.EXPECT().
			New(ctx, oidc.ClientConfig{
				Config:         in.OIDCConfig,
				CACertFilename: "/path/to/cert",
				SkipTLSVerify:  true,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCFactory: mockOIDCFactory,
			Logger:      mock_logger.New(t),
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
		mockOIDCClient := mock_oidc.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByPassword(ctx, oidc.AuthenticateByPasswordIn{
				Username: "USER",
				Password: "PASS",
			}).
			Return(&oidc.AuthenticateOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCFactory := mock_oidc.NewMockFactoryInterface(ctrl)
		mockOIDCFactory.EXPECT().
			New(ctx, oidc.ClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mockOIDCClient, nil)
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)
		u := Authentication{
			OIDCFactory: mockOIDCFactory,
			Env:         mockEnv,
			Logger:      mock_logger.New(t),
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
		mockOIDCFactory := mock_oidc.NewMockFactoryInterface(ctrl)
		mockOIDCFactory.EXPECT().
			New(ctx, oidc.ClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mock_oidc.NewMockInterface(ctrl), nil)
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("", xerrors.New("error"))
		u := Authentication{
			OIDCFactory: mockOIDCFactory,
			Env:         mockEnv,
			Logger:      mock_logger.New(t),
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
		mockOIDCDecoder := mock_oidc.NewMockDecoderInterface(ctrl)
		mockOIDCDecoder.EXPECT().
			DecodeIDToken("VALID_ID_TOKEN").
			Return(&oidc.DecodedIDToken{
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Authentication{
			OIDCFactory: mock_oidc.NewMockFactoryInterface(ctrl),
			OIDCDecoder: mockOIDCDecoder,
			Logger:      mock_logger.New(t),
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
		mockOIDCDecoder := mock_oidc.NewMockDecoderInterface(ctrl)
		mockOIDCDecoder.EXPECT().
			DecodeIDToken("EXPIRED_ID_TOKEN").
			Return(&oidc.DecodedIDToken{
				IDTokenExpiry: pastTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCClient := mock_oidc.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, oidc.RefreshIn{
				RefreshToken: "VALID_REFRESH_TOKEN",
			}).
			Return(&oidc.AuthenticateOut{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCFactory := mock_oidc.NewMockFactoryInterface(ctrl)
		mockOIDCFactory.EXPECT().
			New(ctx, oidc.ClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCFactory: mockOIDCFactory,
			OIDCDecoder: mockOIDCDecoder,
			Logger:      mock_logger.New(t),
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
		mockOIDCDecoder := mock_oidc.NewMockDecoderInterface(ctrl)
		mockOIDCDecoder.EXPECT().
			DecodeIDToken("EXPIRED_ID_TOKEN").
			Return(&oidc.DecodedIDToken{
				IDTokenExpiry: pastTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCClient := mock_oidc.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, oidc.RefreshIn{
				RefreshToken: "EXPIRED_REFRESH_TOKEN",
			}).
			Return(nil, xerrors.New("token has expired"))
		mockOIDCClient.EXPECT().
			AuthenticateByCode(ctx, oidc.AuthenticateByCodeIn{
				LocalServerPort: []int{10000},
			}).
			Return(&oidc.AuthenticateOut{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockOIDCFactory := mock_oidc.NewMockFactoryInterface(ctrl)
		mockOIDCFactory.EXPECT().
			New(ctx, oidc.ClientConfig{
				Config: in.OIDCConfig,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCFactory: mockOIDCFactory,
			OIDCDecoder: mockOIDCDecoder,
			Logger:      mock_logger.New(t),
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
