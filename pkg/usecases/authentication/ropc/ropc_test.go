package ropc

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/infrastructure/reader/mock_reader"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client/mock_client"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"golang.org/x/xerrors"
)

func TestROPC_Do(t *testing.T) {
	timeout := 5 * time.Second

	t.Run("AskUsernameAndPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{}
		mockClient := mock_client.NewMockInterface(ctrl)
		mockClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		mockReader := mock_reader.NewMockInterface(ctrl)
		mockReader.EXPECT().ReadString(usernamePrompt).Return("USER", nil)
		mockReader.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)
		u := ROPC{
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

	t.Run("UsePassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
			Password: "PASS",
		}
		mockClient := mock_client.NewMockInterface(ctrl)
		mockClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		u := ROPC{
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

	t.Run("AskPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
		}
		mockClient := mock_client.NewMockInterface(ctrl)
		mockClient.EXPECT().
			GetTokenByROPC(gomock.Any(), "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		mockEnv := mock_reader.NewMockInterface(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)
		u := ROPC{
			Reader: mockEnv,
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
		out, err := u.Do(ctx, o, mock_client.NewMockInterface(ctrl))
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})
}
