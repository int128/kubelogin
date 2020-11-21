package credentialplugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/int128/kubelogin/pkg/credentialplugin"
	"github.com/int128/kubelogin/pkg/infrastructure/mutex"
	"github.com/int128/kubelogin/pkg/infrastructure/mutex/mock_mutex"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/credentialplugin/writer/mock_writer"
	"github.com/int128/kubelogin/pkg/oidc"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/int128/kubelogin/pkg/tokencache/repository/mock_repository"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
)

func TestGetToken_Do(t *testing.T) {
	issuedIDTokenExpiration := time.Now().Add(1 * time.Hour).Round(time.Second)
	issuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://accounts.google.com"
		claims.Subject = "YOUR_SUBJECT"
		claims.ExpiresAt = issuedIDTokenExpiration.Unix()
	})
	dummyProvider := oidc.Provider{
		IssuerURL:    "https://accounts.google.com",
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
	}

	t.Run("LeastOptions", func(t *testing.T) {
		var grantOptionSet authentication.GrantOptionSet
		tokenSet := oidc.TokenSet{
			IDToken:      issuedIDToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}
		tokenCacheKey := tokencache.Key{
			IssuerURL:    "https://accounts.google.com",
			ClientID:     "YOUR_CLIENT_ID",
			ClientSecret: "YOUR_CLIENT_SECRET",
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{
			Provider:       dummyProvider,
			TokenCacheDir:  "/path/to/token-cache",
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{TokenSet: tokenSet}, nil)
		tokenCacheRepository := mock_repository.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokenCacheKey).
			Return(nil, errors.New("file not found"))
		tokenCacheRepository.EXPECT().
			Save("/path/to/token-cache", tokenCacheKey, tokenSet)
		credentialPluginWriter := mock_writer.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialplugin.Output{
				Token:  issuedIDToken,
				Expiry: issuedIDTokenExpiration,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			Writer:               credentialPluginWriter,
			Mutex:                setupMutexMock(ctrl),
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("FullOptions", func(t *testing.T) {
		grantOptionSet := authentication.GrantOptionSet{
			ROPCOption: &ropc.Option{Username: "YOUR_USERNAME"},
		}
		tokenSet := oidc.TokenSet{
			IDToken:      issuedIDToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}
		tokenCacheKey := tokencache.Key{
			IssuerURL:      "https://accounts.google.com",
			ClientID:       "YOUR_CLIENT_ID",
			ClientSecret:   "YOUR_CLIENT_SECRET",
			Username:       "YOUR_USERNAME",
			CACertFilename: "/path/to/cert",
			CACertData:     "BASE64ENCODED",
			SkipTLSVerify:  true,
		}
		tlsClientConfig := tlsclientconfig.Config{
			CACertFilename: []string{"/path/to/cert"},
			CACertData:     []string{"BASE64ENCODED"},
			SkipTLSVerify:  true,
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{
			Provider:        dummyProvider,
			TokenCacheDir:   "/path/to/token-cache",
			GrantOptionSet:  grantOptionSet,
			TLSClientConfig: tlsClientConfig,
		}
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:        dummyProvider,
				GrantOptionSet:  grantOptionSet,
				TLSClientConfig: tlsClientConfig,
			}).
			Return(&authentication.Output{TokenSet: tokenSet}, nil)
		tokenCacheRepository := mock_repository.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokenCacheKey).
			Return(nil, errors.New("file not found"))
		tokenCacheRepository.EXPECT().
			Save("/path/to/token-cache", tokenCacheKey, tokenSet)
		credentialPluginWriter := mock_writer.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialplugin.Output{
				Token:  issuedIDToken,
				Expiry: issuedIDTokenExpiration,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			Writer:               credentialPluginWriter,
			Mutex:                setupMutexMock(ctrl),
			Logger:               logger.New(t),
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
			Provider:      dummyProvider,
			TokenCacheDir: "/path/to/token-cache",
		}
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: dummyProvider,
				CachedTokenSet: &oidc.TokenSet{
					IDToken: issuedIDToken,
				},
			}).
			Return(&authentication.Output{
				AlreadyHasValidIDToken: true,
				TokenSet: oidc.TokenSet{
					IDToken: issuedIDToken,
				},
			}, nil)
		tokenCacheRepository := mock_repository.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(&oidc.TokenSet{
				IDToken: issuedIDToken,
			}, nil)
		credentialPluginWriter := mock_writer.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialplugin.Output{
				Token:  issuedIDToken,
				Expiry: issuedIDTokenExpiration,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			Writer:               credentialPluginWriter,
			Mutex:                setupMutexMock(ctrl),
			Logger:               logger.New(t),
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
			Provider:      dummyProvider,
			TokenCacheDir: "/path/to/token-cache",
		}
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: dummyProvider,
			}).
			Return(nil, errors.New("authentication error"))
		tokenCacheRepository := mock_repository.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(nil, errors.New("file not found"))
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			Writer:               mock_writer.NewMockInterface(ctrl),
			Mutex:                setupMutexMock(ctrl),
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}

// Setup a mock that expect the mutex to be lock and unlock
func setupMutexMock(ctrl *gomock.Controller) *mock_mutex.MockInterface {
	mockMutex := mock_mutex.NewMockInterface(ctrl)
	lockValue := &mutex.Lock{Data: "testData"}
	acquireCall := mockMutex.EXPECT().Acquire(gomock.Not(gomock.Nil()), "get-token").Return(lockValue, nil)
	mockMutex.EXPECT().Release(lockValue).Return(nil).After(acquireCall)
	return mockMutex
}
