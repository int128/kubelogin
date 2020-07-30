package ropc

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/reader/mock_reader"
	"github.com/int128/kubelogin/pkg/jwt"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"golang.org/x/xerrors"
)

func TestROPC_Do(t *testing.T) {
	dummyTokenClaims := jwt.Claims{
		Subject: "YOUR_SUBJECT",
		Expiry:  time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC),
		Pretty:  "PRETTY_JSON",
	}
	timeout := 5 * time.Second

	t.Run("AskUsernameAndPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:       "YOUR_ID_TOKEN",
				IDTokenClaims: dummyTokenClaims,
				RefreshToken:  "YOUR_REFRESH_TOKEN",
			}, nil)
		mockReader := mock_reader.NewMockInterface(ctrl)
		mockReader.EXPECT().ReadString(usernamePrompt).Return("USER", nil)
		mockReader.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)
		u := ROPC{
			Reader: mockReader,
			Logger: logger.New(t),
		}
		got, err := u.Do(ctx, o, mockOIDCClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &oidc.TokenSet{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("UsePassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
			Password: "PASS",
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := ROPC{
			Logger: logger.New(t),
		}
		got, err := u.Do(ctx, o, mockOIDCClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &oidc.TokenSet{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("AskPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		mockEnv := mock_reader.NewMockInterface(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)
		u := ROPC{
			Reader: mockEnv,
			Logger: logger.New(t),
		}
		got, err := u.Do(ctx, o, mockOIDCClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &oidc.TokenSet{
			IDToken:       "YOUR_ID_TOKEN",
			RefreshToken:  "YOUR_REFRESH_TOKEN",
			IDTokenClaims: dummyTokenClaims,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("AskPasswordError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
		}
		mockEnv := mock_reader.NewMockInterface(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("", xerrors.New("error"))
		u := ROPC{
			Reader: mockEnv,
			Logger: logger.New(t),
		}
		out, err := u.Do(ctx, o, mock_oidcclient.NewMockInterface(ctrl))
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})
}
