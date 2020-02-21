package authentication

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
	"github.com/int128/kubelogin/pkg/domain/jwt"
	"github.com/int128/kubelogin/pkg/testing/clock"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	testingLogger "github.com/int128/kubelogin/pkg/testing/logger"
	"golang.org/x/xerrors"
)

var cmpIgnoreLogger = cmpopts.IgnoreInterfaces(struct{ logger.Interface }{})

func TestAuthentication_Do(t *testing.T) {
	timeout := 5 * time.Second
	expiryTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	cachedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://issuer.example.com"
		claims.Subject = "SUBJECT"
		claims.ExpiresAt = expiryTime.Unix()
	})
	dummyClaims := jwt.Claims{
		Subject: "SUBJECT",
		Expiry:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		Pretty:  "PRETTY_JSON",
	}

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			IDToken:      cachedIDToken,
		}
		u := Authentication{
			Logger: testingLogger.New(t),
			Clock:  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			AlreadyHasValidIDToken: true,
			IDToken:                cachedIDToken,
			IDTokenClaims: jwt.Claims{
				Subject: "SUBJECT",
				Expiry:  expiryTime,
				Pretty: `{
  "exp": 1577934245,
  "iss": "https://issuer.example.com",
  "sub": "SUBJECT"
}`,
			},
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
			IDToken:      cachedIDToken,
			RefreshToken: "VALID_REFRESH_TOKEN",
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, "VALID_REFRESH_TOKEN").
			Return(&oidcclient.TokenSet{
				IDToken:       "NEW_ID_TOKEN",
				RefreshToken:  "NEW_REFRESH_TOKEN",
				IDTokenClaims: dummyClaims,
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
			Logger: testingLogger.New(t),
			Clock:  clock.Fake(expiryTime.Add(+time.Hour)),
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenClaims: dummyClaims,
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
			IDToken:      cachedIDToken,
			RefreshToken: "EXPIRED_REFRESH_TOKEN",
		}
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
				IDTokenClaims: dummyClaims,
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
			Logger: testingLogger.New(t),
			Clock:  clock.Fake(expiryTime.Add(+time.Hour)),
			AuthCode: &AuthCode{
				Logger: testingLogger.New(t),
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "NEW_ID_TOKEN",
			RefreshToken:  "NEW_REFRESH_TOKEN",
			IDTokenClaims: dummyClaims,
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
				IDTokenClaims: dummyClaims,
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
			Logger: testingLogger.New(t),
			ROPC: &ROPC{
				Logger: testingLogger.New(t),
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenClaims: dummyClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}
