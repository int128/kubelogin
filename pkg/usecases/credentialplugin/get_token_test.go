package credentialplugin

import (
	"context"
	"github.com/int128/kubelogin/pkg/adaptors/mutex"
	"github.com/int128/kubelogin/pkg/adaptors/mutex/mock_mutex"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter/mock_credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache/mock_tokencache"
	"github.com/int128/kubelogin/pkg/oidc"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"golang.org/x/xerrors"
)

func TestGetToken_Do(t *testing.T) {
	issuedIDTokenExpiration := time.Now().Add(1 * time.Hour).Round(time.Second)
	issuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://accounts.google.com"
		claims.Subject = "YOUR_SUBJECT"
		claims.ExpiresAt = issuedIDTokenExpiration.Unix()
	})

	t.Run("FullOptions", func(t *testing.T) {
		var grantOptionSet authentication.GrantOptionSet
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{
			IssuerURL:      "https://accounts.google.com",
			ClientID:       "YOUR_CLIENT_ID",
			ClientSecret:   "YOUR_CLIENT_SECRET",
			TokenCacheDir:  "/path/to/token-cache",
			CACertFilename: "/path/to/cert",
			CACertData:     "BASE64ENCODED",
			SkipTLSVerify:  true,
			GrantOptionSet: grantOptionSet,
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPool.EXPECT().
			AddFile("/path/to/cert")
		mockCertPool.EXPECT().
			AddBase64Encoded("BASE64ENCODED")
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:     "https://accounts.google.com",
					ClientID:      "YOUR_CLIENT_ID",
					ClientSecret:  "YOUR_CLIENT_SECRET",
					CertPool:      mockCertPool,
					SkipTLSVerify: true,
				},
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{
				TokenSet: oidc.TokenSet{
					IDToken:      issuedIDToken,
					RefreshToken: "YOUR_REFRESH_TOKEN",
				},
			}, nil)
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache",
				tokencache.Key{
					IssuerURL:      "https://accounts.google.com",
					ClientID:       "YOUR_CLIENT_ID",
					ClientSecret:   "YOUR_CLIENT_SECRET",
					CACertFilename: "/path/to/cert",
					CACertData:     "BASE64ENCODED",
					SkipTLSVerify:  true,
				}).
			Return(nil, xerrors.New("file not found"))
		tokenCacheRepository.EXPECT().
			Save("/path/to/token-cache",
				tokencache.Key{
					IssuerURL:      "https://accounts.google.com",
					ClientID:       "YOUR_CLIENT_ID",
					ClientSecret:   "YOUR_CLIENT_SECRET",
					CACertFilename: "/path/to/cert",
					CACertData:     "BASE64ENCODED",
					SkipTLSVerify:  true,
				},
				oidc.TokenSet{
					IDToken:      issuedIDToken,
					RefreshToken: "YOUR_REFRESH_TOKEN",
				})
		credentialPluginWriter := mock_credentialpluginwriter.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialpluginwriter.Output{
				Token:  issuedIDToken,
				Expiry: issuedIDTokenExpiration,
			})
		mutex := setupMutexMock(ctrl)
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			NewCertPool:          func() certpool.Interface { return mockCertPool },
			Writer:               credentialPluginWriter,
			Mutex:                mutex,
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("MultiUserOption", func(t *testing.T) {
		username := "YOUR_USERNAME"
		grantOptionSetWithUsername := authentication.GrantOptionSet{
			ROPCOption: &ropc.Option{
				Username: username,
			},
		}
		grantOptionSetWithoutUsername := authentication.GrantOptionSet{}

		anotherIssuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
			claims.Issuer = "https://accounts.google.com"
			claims.Subject = "YOUR_SUBJECT_2"
			claims.ExpiresAt = issuedIDTokenExpiration.Unix()
		})
		tokenSetForUsername := oidc.TokenSet{
			IDToken:      issuedIDToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}
		tokenSetForWithoutUsername := oidc.TokenSet{
			IDToken:      anotherIssuedIDToken,
			RefreshToken: "YOUR_REFRESH_TOKEN",
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		inWithUsername := Input{
			IssuerURL:      "https://accounts.google.com",
			ClientID:       "YOUR_CLIENT_ID",
			ClientSecret:   "YOUR_CLIENT_SECRET",
			TokenCacheDir:  "/path/to/token-cache",
			CACertFilename: "/path/to/cert",
			CACertData:     "BASE64ENCODED",
			SkipTLSVerify:  true,
			GrantOptionSet: grantOptionSetWithUsername,
		}
		inWithoutUsername := Input{
			IssuerURL:      "https://accounts.google.com",
			ClientID:       "YOUR_CLIENT_ID",
			ClientSecret:   "YOUR_CLIENT_SECRET",
			TokenCacheDir:  "/path/to/token-cache",
			CACertFilename: "/path/to/cert",
			CACertData:     "BASE64ENCODED",
			SkipTLSVerify:  true,
			GrantOptionSet: grantOptionSetWithoutUsername,
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPool.EXPECT().
			AddFile("/path/to/cert").Times(2)
		mockCertPool.EXPECT().
			AddBase64Encoded("BASE64ENCODED").Times(2)
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:     "https://accounts.google.com",
					ClientID:      "YOUR_CLIENT_ID",
					ClientSecret:  "YOUR_CLIENT_SECRET",
					CertPool:      mockCertPool,
					SkipTLSVerify: true,
				},
				GrantOptionSet: grantOptionSetWithUsername,
				CachedTokenSet: &tokenSetForUsername,
			}).
			Return(&authentication.Output{
				TokenSet: tokenSetForUsername,
			}, nil)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:     "https://accounts.google.com",
					ClientID:      "YOUR_CLIENT_ID",
					ClientSecret:  "YOUR_CLIENT_SECRET",
					CertPool:      mockCertPool,
					SkipTLSVerify: true,
				},
				GrantOptionSet: grantOptionSetWithoutUsername,
				CachedTokenSet: &tokenSetForWithoutUsername,
			}).
			Return(&authentication.Output{
				TokenSet: tokenSetForWithoutUsername,
			}, nil)
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:      "https://accounts.google.com",
				ClientID:       "YOUR_CLIENT_ID",
				ClientSecret:   "YOUR_CLIENT_SECRET",
				CACertFilename: "/path/to/cert",
				CACertData:     "BASE64ENCODED",
				SkipTLSVerify:  true,
				Username:       username,
			}).
			Return(&tokenSetForUsername, nil)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:      "https://accounts.google.com",
				ClientID:       "YOUR_CLIENT_ID",
				ClientSecret:   "YOUR_CLIENT_SECRET",
				CACertFilename: "/path/to/cert",
				CACertData:     "BASE64ENCODED",
				SkipTLSVerify:  true,
				Username:       "",
			}).
			Return(&tokenSetForWithoutUsername, nil)
		tokenCacheRepository.EXPECT().
			Save("/path/to/token-cache",
				tokencache.Key{
					IssuerURL:      "https://accounts.google.com",
					ClientID:       "YOUR_CLIENT_ID",
					ClientSecret:   "YOUR_CLIENT_SECRET",
					CACertFilename: "/path/to/cert",
					CACertData:     "BASE64ENCODED",
					SkipTLSVerify:  true,
					Username:       username,
				},
				tokenSetForUsername)
		tokenCacheRepository.EXPECT().
			Save("/path/to/token-cache",
				tokencache.Key{
					IssuerURL:      "https://accounts.google.com",
					ClientID:       "YOUR_CLIENT_ID",
					ClientSecret:   "YOUR_CLIENT_SECRET",
					CACertFilename: "/path/to/cert",
					CACertData:     "BASE64ENCODED",
					SkipTLSVerify:  true,
					Username:       "",
				},
				tokenSetForWithoutUsername)
		credentialPluginWriter := mock_credentialpluginwriter.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialpluginwriter.Output{
				Token:  issuedIDToken,
				Expiry: issuedIDTokenExpiration,
			})
		credentialPluginWriter.EXPECT().
			Write(credentialpluginwriter.Output{
				Token:  anotherIssuedIDToken,
				Expiry: issuedIDTokenExpiration,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			NewCertPool:          func() certpool.Interface { return mockCertPool },
			Writer:               credentialPluginWriter,
			Logger:               logger.New(t),
		}
		if err := u.Do(ctx, inWithUsername); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		if err := u.Do(ctx, inWithoutUsername); err != nil {
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
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					CertPool:     mockCertPool,
				},
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
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(&oidc.TokenSet{
				IDToken: issuedIDToken,
			}, nil)
		credentialPluginWriter := mock_credentialpluginwriter.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialpluginwriter.Output{
				Token:  issuedIDToken,
				Expiry: issuedIDTokenExpiration,
			})
		mutex := setupMutexMock(ctrl)
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			NewCertPool:          func() certpool.Interface { return mockCertPool },
			Writer:               credentialPluginWriter,
			Mutex:                mutex,
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
			IssuerURL:     "https://accounts.google.com",
			ClientID:      "YOUR_CLIENT_ID",
			ClientSecret:  "YOUR_CLIENT_SECRET",
			TokenCacheDir: "/path/to/token-cache",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					CertPool:     mockCertPool,
				},
			}).
			Return(nil, xerrors.New("authentication error"))
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(nil, xerrors.New("file not found"))
		mutex := setupMutexMock(ctrl)
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			NewCertPool:          func() certpool.Interface { return mockCertPool },
			Writer:               mock_credentialpluginwriter.NewMockInterface(ctrl),
			Mutex:                mutex,
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
