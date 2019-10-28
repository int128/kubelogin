package credentialplugin

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin/mock_credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache/mock_tokencache"
	"github.com/int128/kubelogin/pkg/usecases/auth"
	"github.com/int128/kubelogin/pkg/usecases/auth/mock_auth"
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
		mockAuthentication := mock_auth.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, auth.Input{
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
				BindAddress:     []string{"127.0.0.1:8000"},
				SkipOpenBrowser: true,
				Username:        "USER",
				Password:        "PASS",
				CACertFilename:  "/path/to/cert",
				SkipTLSVerify:   true,
			}).
			Return(&auth.Output{
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
		mockAuthentication := mock_auth.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, auth.Input{
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					IDToken:      "VALID_ID_TOKEN",
				},
			}).
			Return(&auth.Output{
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
		mockAuthentication := mock_auth.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, auth.Input{
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
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
			Interaction:          mock_credentialplugin.NewMockInterface(ctrl),
			Logger:               mock_logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
