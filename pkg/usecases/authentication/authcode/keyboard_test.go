package authcode

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/infrastructure/reader"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/stretchr/testify/mock"
)

func TestKeyboard_Do(t *testing.T) {
	timeout := 5 * time.Second

	t.Run("Success", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &KeyboardOption{
			AuthRequestExtraParams: map[string]string{"ttl": "86400", "reauth": "true"},
		}
		mockClient := client.NewMockInterface(t)
		mockClient.EXPECT().
			SupportedPKCEMethods().
			Return(nil)
		mockClient.EXPECT().
			GetAuthCodeURL(mock.Anything).
			Run(func(in client.AuthCodeURLInput) {
				if diff := cmp.Diff(o.AuthRequestExtraParams, in.AuthRequestExtraParams); diff != "" {
					t.Errorf("AuthRequestExtraParams mismatch (-want +got):\n%s", diff)
				}
			}).
			Return("https://issuer.example.com/auth")
		mockClient.EXPECT().
			ExchangeAuthCode(mock.Anything, mock.Anything).
			Run(func(_ context.Context, in client.ExchangeAuthCodeInput) {
				if in.Code != "YOUR_AUTH_CODE" {
					t.Errorf("Code wants YOUR_AUTH_CODE but was %s", in.Code)
				}
			}).
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		mockReader := reader.NewMockInterface(t)
		mockReader.EXPECT().
			ReadString(keyboardPrompt).
			Return("YOUR_AUTH_CODE", nil)
		u := Keyboard{
			Reader: mockReader,
			Logger: logger.New(t),
		}
		got, err := u.Do(ctx, o, mockClient)
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
