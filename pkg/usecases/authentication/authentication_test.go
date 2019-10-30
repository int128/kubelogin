package authentication

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/adaptors/env/mock_env"
	"github.com/int128/kubelogin/pkg/adaptors/jwtdecoder"
	"github.com/int128/kubelogin/pkg/adaptors/jwtdecoder/mock_jwtdecoder"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient/mock_oidcclient"
	"golang.org/x/xerrors"
)

func TestAuthentication_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	pastTime := time.Now().Add(-time.Hour)  //TODO: inject time service
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service
	timeout := 5 * time.Second

	t.Run("AuthorizationCodeFlow", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		in := Input{
			AuthCodeOption: &AuthCodeOption{
				BindAddress:     []string{"127.0.0.1:8000"},
				SkipOpenBrowser: true,
			},
			CertPool:      mockCertPool,
			SkipTLSVerify: true,
			IssuerURL:     "https://issuer.example.com",
			ClientID:      "YOUR_CLIENT_ID",
			ClientSecret:  "YOUR_CLIENT_SECRET",
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
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:     "https://issuer.example.com",
				ClientID:      "YOUR_CLIENT_ID",
				ClientSecret:  "YOUR_CLIENT_SECRET",
				CertPool:      mockCertPool,
				SkipTLSVerify: true,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			Logger:            mock_logger.New(t),
		}
		out, err := u.Do(ctx, in)
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

	t.Run("AuthorizationCodeFlow/OpenBrowser", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			AuthCodeOption: &AuthCodeOption{
				BindAddress: []string{"127.0.0.1:8000"},
			},
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
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
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(mockOIDCClient, nil)
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().
			OpenBrowser("LOCAL_SERVER_URL")
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			Logger:            mock_logger.New(t),
			Env:               mockEnv,
		}
		out, err := u.Do(ctx, in)
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

	t.Run("ResourceOwnerPasswordCredentialsFlow/UsePassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			ROPCOption: &ROPCOption{
				Username: "USER",
				Password: "PASS",
			},
			SkipTLSVerify: true,
			IssuerURL:     "https://issuer.example.com",
			ClientID:      "YOUR_CLIENT_ID",
			ClientSecret:  "YOUR_CLIENT_SECRET",
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByPassword(gomock.Any(), "USER", "PASS").
			Return(&oidcclient.TokenSet{
				IDToken:        "YOUR_ID_TOKEN",
				RefreshToken:   "YOUR_REFRESH_TOKEN",
				IDTokenSubject: "YOUR_SUBJECT",
				IDTokenExpiry:  futureTime,
				IDTokenClaims:  dummyTokenClaims,
			}, nil)
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:     "https://issuer.example.com",
				ClientID:      "YOUR_CLIENT_ID",
				ClientSecret:  "YOUR_CLIENT_SECRET",
				SkipTLSVerify: true,
			}).
			Return(mockOIDCClient, nil)
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			Logger:            mock_logger.New(t),
		}
		out, err := u.Do(ctx, in)
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

	t.Run("ResourceOwnerPasswordCredentialsFlow/AskPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			ROPCOption: &ROPCOption{
				Username: "USER",
			},
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
		}
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByPassword(gomock.Any(), "USER", "PASS").
			Return(&oidcclient.TokenSet{
				IDToken:        "YOUR_ID_TOKEN",
				RefreshToken:   "YOUR_REFRESH_TOKEN",
				IDTokenSubject: "YOUR_SUBJECT",
				IDTokenExpiry:  futureTime,
				IDTokenClaims:  dummyTokenClaims,
			}, nil)
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(mockOIDCClient, nil)
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("PASS", nil)
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			Env:               mockEnv,
			Logger:            mock_logger.New(t),
		}
		out, err := u.Do(ctx, in)
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

	t.Run("ResourceOwnerPasswordCredentialsFlow/AskPasswordError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			ROPCOption: &ROPCOption{
				Username: "USER",
			},
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
		}
		mockOIDCClientFactory := mock_oidcclient.NewMockFactoryInterface(ctrl)
		mockOIDCClientFactory.EXPECT().
			New(ctx, oidcclient.Config{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(mock_oidcclient.NewMockInterface(ctrl), nil)
		mockEnv := mock_env.NewMockInterface(ctrl)
		mockEnv.EXPECT().ReadPassword(passwordPrompt).Return("", xerrors.New("error"))
		u := Authentication{
			OIDCClientFactory: mockOIDCClientFactory,
			Env:               mockEnv,
			Logger:            mock_logger.New(t),
		}
		out, err := u.Do(ctx, in)
		if err == nil {
			t.Errorf("err wants non-nil but nil")
		}
		if out != nil {
			t.Errorf("out wants nil but %+v", out)
		}
	})

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
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("VALID_ID_TOKEN").
			Return(&jwtdecoder.Claims{
				Subject: "YOUR_SUBJECT",
				Expiry:  futureTime,
				Pretty:  dummyTokenClaims,
			}, nil)
		u := Authentication{
			OIDCClientFactory: mock_oidcclient.NewMockFactoryInterface(ctrl),
			JWTDecoder:        mockDecoder,
			Logger:            mock_logger.New(t),
		}
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			AlreadyHasValidIDToken: true,
			IDToken:                "VALID_ID_TOKEN",
			IDTokenSubject:         "YOUR_SUBJECT",
			IDTokenExpiry:          futureTime,
			IDTokenClaims:          dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
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
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("EXPIRED_ID_TOKEN").
			Return(&jwtdecoder.Claims{
				Subject: "YOUR_SUBJECT",
				Expiry:  pastTime,
				Pretty:  dummyTokenClaims,
			}, nil)
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, "VALID_REFRESH_TOKEN").
			Return(&oidcclient.TokenSet{
				IDToken:        "NEW_ID_TOKEN",
				RefreshToken:   "NEW_REFRESH_TOKEN",
				IDTokenSubject: "YOUR_SUBJECT",
				IDTokenExpiry:  futureTime,
				IDTokenClaims:  dummyTokenClaims,
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
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:        "NEW_ID_TOKEN",
			RefreshToken:   "NEW_REFRESH_TOKEN",
			IDTokenSubject: "YOUR_SUBJECT",
			IDTokenExpiry:  futureTime,
			IDTokenClaims:  dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("HasExpiredRefreshToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			AuthCodeOption: &AuthCodeOption{
				BindAddress:     []string{"127.0.0.1:8000"},
				SkipOpenBrowser: true,
			},
			IssuerURL:    "https://issuer.example.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			IDToken:      "EXPIRED_ID_TOKEN",
			RefreshToken: "EXPIRED_REFRESH_TOKEN",
		}
		mockDecoder := mock_jwtdecoder.NewMockInterface(ctrl)
		mockDecoder.EXPECT().
			Decode("EXPIRED_ID_TOKEN").
			Return(&jwtdecoder.Claims{
				Subject: "YOUR_SUBJECT",
				Expiry:  pastTime,
				Pretty:  dummyTokenClaims,
			}, nil)
		mockOIDCClient := mock_oidcclient.NewMockInterface(ctrl)
		mockOIDCClient.EXPECT().
			Refresh(ctx, "EXPIRED_REFRESH_TOKEN").
			Return(nil, xerrors.New("token has expired"))
		mockOIDCClient.EXPECT().
			AuthenticateByCode(gomock.Any(), []string{"127.0.0.1:8000"}, gomock.Any()).
			Do(func(_ context.Context, _ []string, readyChan chan<- string) {
				readyChan <- "LOCAL_SERVER_URL"
			}).
			Return(&oidcclient.TokenSet{
				IDToken:        "NEW_ID_TOKEN",
				RefreshToken:   "NEW_REFRESH_TOKEN",
				IDTokenSubject: "YOUR_SUBJECT",
				IDTokenExpiry:  futureTime,
				IDTokenClaims:  dummyTokenClaims,
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
		out, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			IDToken:        "NEW_ID_TOKEN",
			RefreshToken:   "NEW_REFRESH_TOKEN",
			IDTokenSubject: "YOUR_SUBJECT",
			IDTokenExpiry:  futureTime,
			IDTokenClaims:  dummyTokenClaims,
		}
		if diff := deep.Equal(want, out); diff != nil {
			t.Error(diff)
		}
	})
}
