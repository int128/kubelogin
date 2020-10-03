package authcode

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/reader/mock_reader"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/testing/logger"
)

var nonNil = gomock.Not(gomock.Nil())

func TestKeyboard_Do(t *testing.T) {
	timeout := 5 * time.Second

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &KeyboardOption{
			AuthRequestExtraParams: map[string]string{"ttl": "86400", "reauth": "true"},
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().SupportedPKCEMethods()
		mockOIDCClient.EXPECT().
			GetAuthCodeURL(nonNil).
			Do(func(in oidcclient.AuthCodeURLInput) {
				if diff := cmp.Diff(o.AuthRequestExtraParams, in.AuthRequestExtraParams); diff != "" {
					t.Errorf("AuthRequestExtraParams mismatch (-want +got):\n%s", diff)
				}
			}).
			Return("https://issuer.example.com/auth")
		mockOIDCClient.EXPECT().
			ExchangeAuthCode(nonNil, nonNil).
			Do(func(_ context.Context, in oidcclient.ExchangeAuthCodeInput) {
				if in.Code != "YOUR_AUTH_CODE" {
					t.Errorf("Code wants YOUR_AUTH_CODE but was %s", in.Code)
				}
			}).
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		mockReader := mock_reader.NewMockInterface(ctrl)
		mockReader.EXPECT().
			ReadString(keyboardPrompt).
			Return("YOUR_AUTH_CODE", nil)
		u := Keyboard{
			Reader: mockReader,
			Logger: logger.New(t),
		}
		got, err := u.Do(ctx, o, mockOIDCClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &oidc.TokenSet{
			IDToken:      "YOUR_ID_TOKEN",
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}
