package credentialplugin

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter/mock_credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache/mock_tokencache"
	"github.com/int128/kubelogin/pkg/domain/jwt"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
	"golang.org/x/xerrors"
)

func TestGetToken_Do(t *testing.T) {
	dummyTokenClaims := jwt.Claims{
		Subject: "YOUR_SUBJECT",
		Expiry:  time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC),
		Pretty:  "PRETTY_JSON",
	}

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
				IssuerURL:      "https://accounts.google.com",
				ClientID:       "YOUR_CLIENT_ID",
				ClientSecret:   "YOUR_CLIENT_SECRET",
				CertPool:       mockCertPool,
				SkipTLSVerify:  true,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenClaims: dummyTokenClaims,
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
				tokencache.Value{
					IDToken:      "YOUR_ID_TOKEN",
					RefreshToken: "YOUR_REFRESH_TOKEN",
				})
		credentialPluginWriter := mock_credentialpluginwriter.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialpluginwriter.Output{
				Token:  "YOUR_ID_TOKEN",
				Expiry: dummyTokenClaims.Expiry,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			NewCertPool:          func() certpool.Interface { return mockCertPool },
			Writer:               credentialPluginWriter,
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
				IDTokenClaims:          dummyTokenClaims,
			}, nil)
		tokenCacheRepository := mock_tokencache.NewMockInterface(ctrl)
		tokenCacheRepository.EXPECT().
			FindByKey("/path/to/token-cache", tokencache.Key{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(&tokencache.Value{
				IDToken: "VALID_ID_TOKEN",
			}, nil)
		credentialPluginWriter := mock_credentialpluginwriter.NewMockInterface(ctrl)
		credentialPluginWriter.EXPECT().
			Write(credentialpluginwriter.Output{
				Token:  "VALID_ID_TOKEN",
				Expiry: dummyTokenClaims.Expiry,
			})
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			NewCertPool:          func() certpool.Interface { return mockCertPool },
			Writer:               credentialPluginWriter,
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
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			}).
			Return(nil, xerrors.New("file not found"))
		u := GetToken{
			Authentication:       mockAuthentication,
			TokenCacheRepository: tokenCacheRepository,
			NewCertPool:          func() certpool.Interface { return mockCertPool },
			Writer:               mock_credentialpluginwriter.NewMockInterface(ctrl),
			Logger:               mock_logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
