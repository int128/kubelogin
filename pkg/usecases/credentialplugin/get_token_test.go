package credentialplugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/int128/kubelogin/pkg/credentialplugin"
	"github.com/int128/kubelogin/pkg/credentialplugin/writer"
	"github.com/int128/kubelogin/pkg/infrastructure/mutex"
	"github.com/int128/kubelogin/pkg/tokencache/repository"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"

	"github.com/int128/kubelogin/pkg/oidc"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
)

func TestGetToken_Do(t *testing.T) {
	dummyProvider := oidc.Provider{
		IssuerURL:    "https://accounts.google.com",
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
	}
	issuedIDTokenExpiration := time.Now().Add(1 * time.Hour).Round(time.Second)
	issuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://accounts.google.com"
		claims.Subject = "YOUR_SUBJECT"
		claims.ExpiresAt = issuedIDTokenExpiration.Unix()
	})
	issuedTokenSet := oidc.TokenSet{
		IDToken:      issuedIDToken,
		RefreshToken: "YOUR_REFRESH_TOKEN",
	}
	issuedOutput := credentialplugin.Output{
		Token:  issuedIDToken,
		Expiry: issuedIDTokenExpiration,
	}
	grantOptionSet := authentication.GrantOptionSet{
		AuthCodeBrowserOption: &authcode.BrowserOption{
			BindAddress: []string{"127.0.0.1:0"},
		},
	}

	t.Run("NoTokenCache", func(t *testing.T) {
		tokenCacheKey := tokencache.Key{
			IssuerURL:    "https://accounts.google.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
		}
		ctx := context.TODO()
		in := Input{
			Provider:       dummyProvider,
			TokenCacheDir:  "/path/to/token-cache",
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{TokenSet: issuedTokenSet}, nil)
		mockRepository := repository.NewMockInterface(t)
		mockRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokenCacheKey).
			Return(nil, errors.New("file not found"))
		mockRepository.EXPECT().
			Save("/path/to/token-cache", tokenCacheKey, issuedTokenSet).
			Return(nil)
		mockWriter := writer.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: mockRepository,
			Writer:               mockWriter,
			Mutex:                mutex.NewMockInterface(t),
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("NeedBindPortMutex", func(t *testing.T) {
		grantOptionSet := authentication.GrantOptionSet{
			AuthCodeBrowserOption: &authcode.BrowserOption{
				BindAddress: []string{"127.0.0.1:8080"},
			},
		}
		tokenCacheKey := tokencache.Key{
			IssuerURL:    "https://accounts.google.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
		}

		ctx := context.TODO()
		in := Input{
			Provider:       dummyProvider,
			TokenCacheDir:  "/path/to/token-cache",
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{TokenSet: issuedTokenSet}, nil)
		mockRepository := repository.NewMockInterface(t)
		mockRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokenCacheKey).
			Return(nil, errors.New("file not found"))
		mockRepository.EXPECT().
			Save("/path/to/token-cache", tokenCacheKey, issuedTokenSet).
			Return(nil)
		mockWriter := writer.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		mockMutex := mutex.NewMockInterface(t)
		mockMutex.EXPECT().
			Acquire(ctx, "get-token-8080").
			Return(&mutex.Lock{Data: "testData"}, nil)
		mockMutex.EXPECT().
			Release(&mutex.Lock{Data: "testData"}).
			Return(nil)
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: mockRepository,
			Writer:               mockWriter,
			Mutex:                mockMutex,
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("ROPC", func(t *testing.T) {
		grantOptionSet := authentication.GrantOptionSet{
			ROPCOption: &ropc.Option{Username: "YOUR_USERNAME"},
		}
		tokenCacheKey := tokencache.Key{
			IssuerURL:    "https://accounts.google.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
			Username:     "YOUR_USERNAME",
		}

		ctx := context.TODO()
		in := Input{
			Provider:       dummyProvider,
			TokenCacheDir:  "/path/to/token-cache",
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{TokenSet: issuedTokenSet}, nil)
		mockRepository := repository.NewMockInterface(t)
		mockRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokenCacheKey).
			Return(nil, errors.New("file not found"))
		mockRepository.EXPECT().
			Save("/path/to/token-cache", tokenCacheKey, issuedTokenSet).
			Return(nil)
		mockWriter := writer.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: mockRepository,
			Writer:               mockWriter,
			Mutex:                mutex.NewMockInterface(t),
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctx := context.TODO()
		in := Input{
			Provider:       dummyProvider,
			TokenCacheDir:  "/path/to/token-cache",
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				CachedTokenSet: &issuedTokenSet,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{
				AlreadyHasValidIDToken: true,
				TokenSet:               issuedTokenSet,
			}, nil)
		mockRepository := repository.NewMockInterface(t)
		mockRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(&issuedTokenSet, nil)
		mockWriter := writer.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: mockRepository,
			Writer:               mockWriter,
			Mutex:                mutex.NewMockInterface(t),
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		ctx := context.TODO()
		in := Input{
			Provider:       dummyProvider,
			TokenCacheDir:  "/path/to/token-cache",
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(nil, errors.New("authentication error"))
		mockRepository := repository.NewMockInterface(t)
		mockRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(nil, errors.New("file not found"))
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: mockRepository,
			Writer:               writer.NewMockInterface(t),
			Mutex:                mutex.NewMockInterface(t),
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
