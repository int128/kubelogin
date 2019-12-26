package authentication

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/adaptors/jwtdecoder/mock_jwtdecoder"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
	"github.com/int128/kubelogin/pkg/domain/oidc"
	"golang.org/x/xerrors"
)

func TestAuthentication_Do(t *testing.T) {
	pastTime := time.Now().Add(-time.Hour)  //TODO: inject time service
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service
	timeout := 5 * time.Second

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
		claims := newClaims(futureTime)
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("VALID_ID_TOKEN").
			Return(&claims, nil)
		u := Authentication{
			OIDCClientFactory: mock_oidcclient.NewMockFactoryInterface(ctrl),
			JWTDecoder:        mockDecoder,
			Logger:            mock_logger.New(t),
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			AlreadyHasValidIDToken: true,
			IDToken:                "VALID_ID_TOKEN",
			IDTokenClaims:          claims,
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
		claims := newClaims(pastTime)
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("EXPIRED_ID_TOKEN").
			Return(&claims, nil)
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, "VALID_REFRESH_TOKEN").
			Return(&oidcclient.TokenSet{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenClaims: claims,
			}, nil)
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			JWTDecoder:        mockDecoder,
			Logger:            mock_logger.New(t),
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenClaims: claims,
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
		claims := newClaims(pastTime)
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("EXPIRED_ID_TOKEN").
			Return(&claims, nil)
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
				IDTokenClaims: claims,
			}, nil)
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			JWTDecoder:        mockDecoder,
			Logger:            mock_logger.New(t),
			AuthCode: &AuthCode{
				Logger: mock_logger.New(t),
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenClaims: claims,
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
		claims := newClaims(futureTime)
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidcclient.TokenSet{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenClaims: claims,
			}, nil)
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			Logger:            mock_logger.New(t),
			ROPC: &ROPC{
				Logger: mock_logger.New(t),
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenClaims: claims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func newClaims(expiry time.Time) oidc.Claims {
	return oidc.Claims{
		Subject: "YOUR_SUBJECT",
		Expiry:  expiry,
		Pretty:  map[string]string{"sub": "YOUR_SUBJECT"},
	}
}
