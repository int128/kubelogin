package credentialplugin

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/pkg/models/credentialplugin"
	"github.com/int128/kubelogin/pkg/models/kubeconfig"
	"github.com/int128/kubelogin/pkg/usecases"
	"github.com/int128/kubelogin/pkg/usecases/mock_usecases"
	"golang.org/x/xerrors"
)

func TestGetToken_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service

	t.Run("FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.GetTokenIn{
			IssuerURL:       "https://accounts.google.com",
			ClientID:        "YOUR_CLIENT_ID",
			ClientSecret:    "YOUR_CLIENT_SECRET",
			TokenCacheDir:   "/path/to/token-cache",
			ListenPort:      []int{10000},
			SkipOpenBrowser: true,
			Username:        "USER",
			Password:        "PASS",
			CACertFilename:  "/path/to/cert",
			SkipTLSVerify:   true,
		}
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
				ListenPort:      []int{10000},
				SkipOpenBrowser: true,
				Username:        "USER",
				Password:        "PASS",
				CACertFilename:  "/path/to/cert",
				SkipTLSVerify:   true,
			}).
			Return(&usecases.AuthenticationOut{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		tokenCacheRepository := mock_adaptors.NewMockTokenCacheRepository(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", credentialplugin.TokenCacheKey{
				IssuerURL: "https://accounts.google.com",
				ClientID:  "YOUR_CLIENT_ID",
			}).
			Return(nil, xerrors.New("file not found"))
		tokenCacheRepository.EXPECT().
			Save("/path/to/token-cache",
				credentialplugin.TokenCacheKey{
					IssuerURL: "https://accounts.google.com",
					ClientID:  "YOUR_CLIENT_ID",
				},
				credentialplugin.TokenCache{
					IDToken:      "YOUR_ID_TOKEN",
					RefreshToken: "YOUR_REFRESH_TOKEN",
				})
		credentialPluginInteraction := mock_adaptors.NewMockCredentialPluginInteraction(ctrl)
		credentialPluginInteraction.EXPECT().
			Write(credentialplugin.Output{
				Token:  "YOUR_ID_TOKEN",
				Expiry: futureTime,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			Interaction:          credentialPluginInteraction,
			Logger:               mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.GetTokenIn{
			IssuerURL:     "https://accounts.google.com",
			ClientID:      "YOUR_CLIENT_ID",
			ClientSecret:  "YOUR_CLIENT_SECRET",
			TokenCacheDir: "/path/to/token-cache",
		}
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					IDToken:      "VALID_ID_TOKEN",
				},
			}).
			Return(&usecases.AuthenticationOut{
				AlreadyHasValidIDToken: true,
				IDToken:                "VALID_ID_TOKEN",
				IDTokenExpiry:          futureTime,
				IDTokenClaims:          dummyTokenClaims,
			}, nil)
		tokenCacheRepository := mock_adaptors.NewMockTokenCacheRepository(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", credentialplugin.TokenCacheKey{
				IssuerURL: "https://accounts.google.com",
				ClientID:  "YOUR_CLIENT_ID",
			}).
			Return(&credentialplugin.TokenCache{
				IDToken: "VALID_ID_TOKEN",
			}, nil)
		credentialPluginInteraction := mock_adaptors.NewMockCredentialPluginInteraction(ctrl)
		credentialPluginInteraction.EXPECT().
			Write(credentialplugin.Output{
				Token:  "VALID_ID_TOKEN",
				Expiry: futureTime,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			Interaction:          credentialPluginInteraction,
			Logger:               mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := usecases.GetTokenIn{
			IssuerURL:     "https://accounts.google.com",
			ClientID:      "YOUR_CLIENT_ID",
			ClientSecret:  "YOUR_CLIENT_SECRET",
			TokenCacheDir: "/path/to/token-cache",
		}
		mockAuthentication := mock_usecases.NewMockAuthentication(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, usecases.AuthenticationIn{
				OIDCConfig: kubeconfig.OIDCConfig{
					IDPIssuerURL: "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
			}).
			Return(nil, xerrors.New("authentication error"))
		tokenCacheRepository := mock_adaptors.NewMockTokenCacheRepository(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", credentialplugin.TokenCacheKey{
				IssuerURL: "https://accounts.google.com",
				ClientID:  "YOUR_CLIENT_ID",
			}).
			Return(nil, xerrors.New("file not found"))
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			Interaction:          mock_adaptors.NewMockCredentialPluginInteraction(ctrl),
			Logger:               mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
