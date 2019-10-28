package credentialplugin

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin/mock_credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache/mock_tokencache"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
	"golang.org/x/xerrors"
)

func TestGetToken_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service

	t.Run("FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{
			IssuerURL:       "https://accounts.google.com",
			ClientID:        "YOUR_CLIENT_ID",
			ClientSecret:    "YOUR_CLIENT_SECRET",
			TokenCacheDir:   "/path/to/token-cache",
			BindAddress:     []string{"127.0.0.1:8000"},
			SkipOpenBrowser: true,
			Username:        "USER",
			Password:        "PASS",
			CACertFilename:  "/path/to/cert",
			SkipTLSVerify:   true,
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPool.EXPECT().
			AddFile("/path/to/cert")
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockCertPoolFactory.EXPECT().
			New().
			Return(mockCertPool)
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				IssuerURL:       "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				BindAddress:     []string{"127.0.0.1:8000"},
				SkipOpenBrowser: true,
				Username:        "USER",
				Password:        "PASS",
				CertPool:        mockCertPool,
				SkipTLSVerify:   true,
			}).
			Return(&authentication.Output{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL: "https://accounts.google.com",
				ClientID:  "YOUR_CLIENT_ID",
			}).
			Return(nil, xerrors.New("file not found"))
		tokenCacheRepository.EXPECT().
			Save("/path/to/token-cache",
				tokencache.Key{
					IssuerURL: "https://accounts.google.com",
					ClientID:  "YOUR_CLIENT_ID",
				},
				tokencache.TokenCache{
					IDToken:      "YOUR_ID_TOKEN",
					RefreshToken: "YOUR_REFRESH_TOKEN",
				})
		credentialPluginInteraction := mock_credentialplugin.NewMockInterface(ctrl)
		credentialPluginInteraction.EXPECT().
			Write(credentialplugin.Output{
				Token:  "YOUR_ID_TOKEN",
				Expiry: futureTime,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			CertPoolFactory:      mockCertPoolFactory,
			Interaction:          credentialPluginInteraction,
			Logger:               mock_logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{
			IssuerURL:     "https://accounts.google.com",
			ClientID:      "YOUR_CLIENT_ID",
			ClientSecret:  "YOUR_CLIENT_SECRET",
			TokenCacheDir: "/path/to/token-cache",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockCertPoolFactory.EXPECT().
			New().
			Return(mockCertPool)
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				IDToken:      "VALID_ID_TOKEN",
				CertPool:     mockCertPool,
			}).
			Return(&authentication.Output{
				AlreadyHasValidIDToken: true,
				IDToken:                "VALID_ID_TOKEN",
				IDTokenExpiry:          futureTime,
				IDTokenClaims:          dummyTokenClaims,
			}, nil)
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL: "https://accounts.google.com",
				ClientID:  "YOUR_CLIENT_ID",
			}).
			Return(&tokencache.TokenCache{
				IDToken: "VALID_ID_TOKEN",
			}, nil)
		credentialPluginInteraction := mock_credentialplugin.NewMockInterface(ctrl)
		credentialPluginInteraction.EXPECT().
			Write(credentialplugin.Output{
				Token:  "VALID_ID_TOKEN",
				Expiry: futureTime,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			CertPoolFactory:      mockCertPoolFactory,
			Interaction:          credentialPluginInteraction,
			Logger:               mock_logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{
			IssuerURL:     "https://accounts.google.com",
			ClientID:      "YOUR_CLIENT_ID",
			ClientSecret:  "YOUR_CLIENT_SECRET",
			TokenCacheDir: "/path/to/token-cache",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockCertPoolFactory.EXPECT().
			New().
			Return(mockCertPool)
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				CertPool:     mockCertPool,
			}).
			Return(nil, xerrors.New("authentication error"))
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL: "https://accounts.google.com",
				ClientID:  "YOUR_CLIENT_ID",
			}).
			Return(nil, xerrors.New("file not found"))
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			CertPoolFactory:      mockCertPoolFactory,
			Interaction:          mock_credentialplugin.NewMockInterface(ctrl),
			Logger:               mock_logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
