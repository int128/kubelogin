package authentication

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/int128/kubelogin/pkg/adaptors/env/mock_env"
	"github.com/int128/kubelogin/pkg/adaptors/jwtdecoder/mock_jwtdecoder"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
	"github.com/int128/kubelogin/pkg/domain/oidc"
	"golang.org/x/xerrors"
)

var cmpIgnoreLogger = cmpopts.IgnoreInterfaces(struct{ logger.Interface }{})

func TestAuthentication_Do(t *testing.T) {
	dummyTokenClaims := oidc.Claims{
		Subject: "YOUR_SUBJECT",
		Expiry:  time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC),
		Pretty:  map[string]string{"sub": "YOUR_SUBJECT"},
	}
	timeBeforeExpiry := time.Date(2019, 1, 2, 1, 0, 0, 0, time.UTC)
	timeAfterExpiry := time.Date(2019, 1, 2, 4, 0, 0, 0, time.UTC)
	timeout := 5 * time.Second
	testingLogger := mock_logger.New(t)

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			IDToken:      "VALID_ID_TOKEN",
		}
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().
			Now().
			Return(timeBeforeExpiry)
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("VALID_ID_TOKEN").
			Return(&dummyTokenClaims, nil)
		u := Authentication{
			JWTDecoder: mockDecoder,
			Logger:     testingLogger,
			Env:        mockEnv,
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			AlreadyHasValidIDToken: true,
			IDToken:                "VALID_ID_TOKEN",
			IDTokenClaims:          dummyTokenClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("HasValidRefreshToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			IDToken:      "EXPIRED_ID_TOKEN",
			RefreshToken: "VALID_REFRESH_TOKEN",
		}
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().
			Now().
			Return(timeAfterExpiry)
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("EXPIRED_ID_TOKEN").
			Return(&dummyTokenClaims, nil)
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, "VALID_REFRESH_TOKEN").
			Return(&oidcclient.TokenSet{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Authentication{
			NewOIDCClient: func(_ context.Context, got oidcclient.Config) (oidcclient.Interface, error) {
				want := oidcclient.Config{
					IssuerURL:    "https://issuer.example.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				}
				if diff := cmp.Diff(want, got, cmpIgnoreLogger); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
				return mockOIDCClient, nil
			},
			JWTDecoder: mockDecoder,
			Logger:     testingLogger,
			Env:        mockEnv,
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("HasExpiredRefreshToken/AuthCode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			GrantOptionSet: GrantOptionSet{
				AuthCodeOption: &AuthCodeOption{
					BindAddress:     []string{"127.0.0.1:8000"},
					SkipOpenBrowser: true,
				},
			},
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			IDToken:      "EXPIRED_ID_TOKEN",
			RefreshToken: "EXPIRED_REFRESH_TOKEN",
		}
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().
			Now().
			Return(timeAfterExpiry)
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("EXPIRED_ID_TOKEN").
			Return(&dummyTokenClaims, nil)
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, "EXPIRED_REFRESH_TOKEN").
			Return(nil, xerrors.New("token has expired"))
		mockOIDCClient.EXPECT().
			GetTokenByAuthCode(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_ context.Context, _ oidcclient.GetTokenByAuthCodeInput, readyChan chan<- string) {
				readyChan <- "LOCAL_SERVER_URL"
			}).
			Return(&oidcclient.TokenSet{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Authentication{
			NewOIDCClient: func(_ context.Context, got oidcclient.Config) (oidcclient.Interface, error) {
				want := oidcclient.Config{
					IssuerURL:    "https://issuer.example.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				}
				if diff := cmp.Diff(want, got, cmpIgnoreLogger); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
				return mockOIDCClient, nil
			},
			JWTDecoder: mockDecoder,
			Logger:     testingLogger,
			Env:        mockEnv,
			AuthCode: &AuthCode{
				Logger: testingLogger,
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NoToken/ROPC", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			GrantOptionSet: GrantOptionSet{
				ROPCOption: &ROPCOption{
					Username: "USER",
					Password: "PASS",
				},
			},
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidcclient.TokenSet{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Authentication{
			NewOIDCClient: func(_ context.Context, got oidcclient.Config) (oidcclient.Interface, error) {
				want := oidcclient.Config{
					IssuerURL:    "https://issuer.example.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				}
				if diff := cmp.Diff(want, got, cmpIgnoreLogger); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
				return mockOIDCClient, nil
			},
			Logger: testingLogger,
			ROPC: &ROPC{
				Logger: testingLogger,
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}
