package tokenexchange

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/oidc/client_mock"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/testing/logger"
)

func TestTokenExchange_Do(t *testing.T) {
	t.Run("MissingSubjectToken", func(t *testing.T) {
		ctx := context.TODO()
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		}
		_, err := u.Do(ctx, in, client_mock.NewMockInterface(t))
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("MissingSubjectTokenType", func(t *testing.T) {
		ctx := context.TODO()
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			SubjectToken: "SUBJECT_TOKEN",
		}
		out, err := u.Do(ctx, in, client_mock.NewMockInterface(t))
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})

	t.Run("ActorTokenWithoutActorTokenType", func(t *testing.T) {
		ctx := context.TODO()
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			ActorToken:       "ACTOR_TOKEN",
		}
		out, err := u.Do(ctx, in, client_mock.NewMockInterface(t))
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})

	t.Run("ActorTokenTypeWithoutActorToken", func(t *testing.T) {
		ctx := context.TODO()
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			ActorTokenType:   "urn:ietf:params:oauth:token-type:access_token",
		}
		out, err := u.Do(ctx, in, client_mock.NewMockInterface(t))
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})

	t.Run("Success", func(t *testing.T) {
		ctx := context.TODO()
		mockClient := client_mock.NewMockInterface(t)
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		}
		wantInput := client.GetTokenByTokenExchangeInput{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		}
		testToken := &oidc.TokenSet{
			IDToken:      "YOUR_ID_TOKEN",
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}
		mockClient.EXPECT().GetTokenByTokenExchange(ctx, wantInput).Return(testToken, nil).Once()
		got, err := u.Do(ctx, in, mockClient)
		if err != nil {
			t.Errorf("Do returned unexpected error: %v", err)
		}
		if diff := cmp.Diff(testToken, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SuccessWithActorToken", func(t *testing.T) {
		ctx := context.TODO()
		mockClient := client_mock.NewMockInterface(t)
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			ActorToken:       "ACTOR_TOKEN",
			ActorTokenType:   "urn:ietf:params:oauth:token-type:access_token",
		}
		wantInput := client.GetTokenByTokenExchangeInput{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			ActorToken:       "ACTOR_TOKEN",
			ActorTokenType:   "urn:ietf:params:oauth:token-type:access_token",
		}
		testToken := &oidc.TokenSet{
			IDToken:      "YOUR_ID_TOKEN",
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}
		mockClient.EXPECT().GetTokenByTokenExchange(ctx, wantInput).Return(testToken, nil).Once()
		got, err := u.Do(ctx, in, mockClient)
		if err != nil {
			t.Errorf("Do returned unexpected error: %v", err)
		}
		if diff := cmp.Diff(testToken, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SuccessWithExtraParams", func(t *testing.T) {
		ctx := context.TODO()
		mockClient := client_mock.NewMockInterface(t)
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			Resource:           []string{"https://resource.example.com"},
			Audience:           []string{"https://audience.example.com"},
			RequestedTokenType: "urn:ietf:params:oauth:token-type:refresh_token",
			SubjectToken:       "SUBJECT_TOKEN",
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
			AuthRequestExtraParams: map[string]string{
				"audience": "api1",
			},
		}
		wantInput := client.GetTokenByTokenExchangeInput{
			Resource:           []string{"https://resource.example.com"},
			Audience:           []string{"https://audience.example.com"},
			RequestedTokenType: "urn:ietf:params:oauth:token-type:refresh_token",
			SubjectToken:       "SUBJECT_TOKEN",
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
			AuthRequestExtraParams: map[string]string{
				"audience": "api1",
			},
		}
		testToken := &oidc.TokenSet{
			IDToken:      "YOUR_ID_TOKEN",
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}
		mockClient.EXPECT().GetTokenByTokenExchange(ctx, wantInput).Return(testToken, nil).Once()
		got, err := u.Do(ctx, in, mockClient)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		if diff := cmp.Diff(testToken, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ClientError", func(t *testing.T) {
		ctx := context.TODO()
		mockClient := client_mock.NewMockInterface(t)
		u := TokenExchange{
			Logger: logger.New(t),
		}
		in := &TokenExchangeOption{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		}
		wantInput := client.GetTokenByTokenExchangeInput{
			SubjectToken:     "SUBJECT_TOKEN",
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		}
		errTest := errors.New("could not exchange")
		mockClient.EXPECT().GetTokenByTokenExchange(ctx, wantInput).Return(nil, errTest).Once()
		out, err := u.Do(ctx, in, mockClient)
		if !errors.Is(err, errTest) {
			t.Errorf("returned error is not the test error: %v", err)
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})
}
