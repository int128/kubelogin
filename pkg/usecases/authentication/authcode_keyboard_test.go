package authentication

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/adaptors/env/mock_env"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
	"github.com/int128/kubelogin/pkg/domain/jwt"
)

var nonNil = gomock.Not(gomock.Nil())

func TestAuthCodeKeyboard_Do(t *testing.T) {
	dummyTokenClaims := jwt.Claims{
		Subject: "YOUR_SUBJECT",
		Expiry:  time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC),
		Pretty:  "PRETTY_JSON",
	}
	timeout := 5 * time.Second

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			GetAuthCodeURL(nonNil).
			Return("https://issuer.example.com/auth")
		mockOIDCClient.EXPECT().
			ExchangeAuthCode(nonNil, nonNil).
			Do(func(_ context.Context, in oidcclient.ExchangeAuthCodeInput) {
				if in.Code != "YOUR_AUTH_CODE" {
					t.Errorf("Code wants YOUR_AUTH_CODE but was %s", in.Code)
				}
			}).
			Return(&oidcclient.TokenSet{
				IDToken:       "YOUR_ID_TOKEN",
				IDTokenClaims: dummyTokenClaims,
				RefreshToken:  "YOUR_REFRESH_TOKEN",
			}, nil)
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().
			ReadString(authCodeKeyboardPrompt).
			Return("YOUR_AUTH_CODE", nil)
		u := AuthCodeKeyboard{
			Env:    mockEnv,
			Logger: mock_logger.New(t),
		}
		got, err := u.Do(ctx, nil, mockOIDCClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:       "YOUR_ID_TOKEN",
			IDTokenClaims: dummyTokenClaims,
			RefreshToken:  "YOUR_REFRESH_TOKEN",
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}
