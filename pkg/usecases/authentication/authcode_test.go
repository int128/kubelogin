package authentication

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/env/mock_env"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
)

func TestAuthCode_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service
	timeout := 5 * time.Second

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &AuthCodeOption{
			BindAddress:     []string{"127.0.0.1:8000"},
			SkipOpenBrowser: true,
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByCode(gomock.Any(), []string{"127.0.0.1:8000"}, gomock.Any()).
			Do(func(_ context.Context, _ []string, readyChan chan<- string) {
				readyChan <- "LOCAL_SERVER_URL"
			}).
			Return(&oidcclient.TokenSet{
				IDToken:        "YOUR_ID_TOKEN",
				RefreshToken:   "YOUR_REFRESH_TOKEN",
				IDTokenSubject: "YOUR_SUBJECT",
				IDTokenExpiry:  futureTime,
				IDTokenClaims:  dummyTokenClaims,
			}, nil)
		u := AuthCode{
			Logger: mock_logger.New(t),
		}
		out, err := u.Do(ctx, o, mockOIDCClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:        "YOUR_ID_TOKEN",
			RefreshToken:   "YOUR_REFRESH_TOKEN",
			IDTokenSubject: "YOUR_SUBJECT",
			IDTokenExpiry:  futureTime,
			IDTokenClaims:  dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("OpenBrowser", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &AuthCodeOption{
			BindAddress: []string{"127.0.0.1:8000"},
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByCode(gomock.Any(), []string{"127.0.0.1:8000"}, gomock.Any()).
			Do(func(_ context.Context, _ []string, readyChan chan<- string) {
				readyChan <- "LOCAL_SERVER_URL"
			}).
			Return(&oidcclient.TokenSet{
				IDToken:        "YOUR_ID_TOKEN",
				RefreshToken:   "YOUR_REFRESH_TOKEN",
				IDTokenSubject: "YOUR_SUBJECT",
				IDTokenExpiry:  futureTime,
				IDTokenClaims:  dummyTokenClaims,
			}, nil)
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().
			OpenBrowser("LOCAL_SERVER_URL")
		u := AuthCode{
			Logger: mock_logger.New(t),
			Env:    mockEnv,
		}
		out, err := u.Do(ctx, o, mockOIDCClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:        "YOUR_ID_TOKEN",
			RefreshToken:   "YOUR_REFRESH_TOKEN",
			IDTokenSubject: "YOUR_SUBJECT",
			IDTokenExpiry:  futureTime,
			IDTokenClaims:  dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})
}
