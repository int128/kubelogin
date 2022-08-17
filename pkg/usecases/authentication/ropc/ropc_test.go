package ropc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/infrastructure/reader"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/stretchr/testify/mock"
)

func TestROPC_Do(t *testing.T) {
	timeout := 5 * time.Second

	t.Run("AskUsernameAndPassword", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{}
		mockClient := client.NewMockInterface(t)
		mockClient.EXPECT().
			GetTokenByROPC(mock.Anything, "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		mockReader := reader.NewMockInterface(t)
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
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
			Password: "PASS",
		}
		mockClient := client.NewMockInterface(t)
		mockClient.EXPECT().
			GetTokenByROPC(mock.Anything, "USER", "PASS").
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
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
		}
		mockClient := client.NewMockInterface(t)
		mockClient.EXPECT().
			GetTokenByROPC(mock.Anything, "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		mockEnv := reader.NewMockInterface(t)
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
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		o := &Option{
			Username: "USER",
		}
		mockEnv := reader.NewMockInterface(t)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("", errors.New("error"))
		u := ROPC{
			Reader: mockEnv,
			Logger: logger.New(t),
		}
		out, err := u.Do(ctx, o, client.NewMockInterface(t))
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})
}
