package standalone

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig/mock_kubeconfig"
	"github.com/int128/kubelogin/pkg/oidc"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
	"golang.org/x/xerrors"
)

func TestStandalone_Do(t *testing.T) {
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
			KubeconfigFilename: "/path/to/kubeconfig",
			KubeconfigContext:  "theContext",
			KubeconfigUser:     "theUser",
			CACertFilename:     "/path/to/cert1",
			CACertData:         "BASE64ENCODED1",
			SkipTLSVerify:      true,
			GrantOptionSet:     grantOptionSet,
		}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin:            "/path/to/kubeconfig",
			UserName:                    "theUser",
			IDPIssuerURL:                "https://accounts.google.com",
			ClientID:                    "YOUR_CLIENT_ID",
			ClientSecret:                "YOUR_CLIENT_SECRET",
			IDPCertificateAuthority:     "/path/to/cert2",
			IDPCertificateAuthorityData: "BASE64ENCODED2",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPool.EXPECT().
			AddFile("/path/to/cert1")
		mockCertPool.EXPECT().
			AddFile("/path/to/cert2")
		mockCertPool.EXPECT().
			AddBase64Encoded("BASE64ENCODED1")
		mockCertPool.EXPECT().
			AddBase64Encoded("BASE64ENCODED2")
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("/path/to/kubeconfig", kubeconfig.ContextName("theContext"), kubeconfig.UserName("theUser")).
			Return(currentAuthProvider, nil)
		mockKubeconfig.EXPECT().
			UpdateAuthProvider(&kubeconfig.AuthProvider{
				LocationOfOrigin:            "/path/to/kubeconfig",
				UserName:                    "theUser",
				IDPIssuerURL:                "https://accounts.google.com",
				ClientID:                    "YOUR_CLIENT_ID",
				ClientSecret:                "YOUR_CLIENT_SECRET",
				IDPCertificateAuthority:     "/path/to/cert2",
				IDPCertificateAuthorityData: "BASE64ENCODED2",
				IDToken:                     issuedIDToken,
				RefreshToken:                "YOUR_REFRESH_TOKEN",
			})
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
		u := Standalone{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			NewCertPool:    func() certpool.Interface { return mockCertPool },
			Logger:         logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "theUser",
			IDPIssuerURL:     "https://accounts.google.com",
			ClientID:         "YOUR_CLIENT_ID",
			ClientSecret:     "YOUR_CLIENT_SECRET",
			IDToken:          issuedIDToken,
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
					CertPool:     mockCertPool,
				},
				IDToken: issuedIDToken,
			}).
			Return(&authentication.Output{
				AlreadyHasValidIDToken: true,
				TokenSet: oidc.TokenSet{
					IDToken: issuedIDToken,
				},
			}, nil)
		u := Standalone{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			NewCertPool:    func() certpool.Interface { return mockCertPool },
			Logger:         logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("NoOIDCConfig", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{}
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(nil, xerrors.New("no oidc config"))
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		u := Standalone{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			Logger:         logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "google",
			IDPIssuerURL:     "https://accounts.google.com",
			ClientID:         "YOUR_CLIENT_ID",
			ClientSecret:     "YOUR_CLIENT_SECRET",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
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
		u := Standalone{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			NewCertPool:    func() certpool.Interface { return mockCertPool },
			Logger:         logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("WriteError", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "google",
			IDPIssuerURL:     "https://accounts.google.com",
			ClientID:         "YOUR_CLIENT_ID",
			ClientSecret:     "YOUR_CLIENT_SECRET",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockKubeconfig.EXPECT().
			UpdateAuthProvider(&kubeconfig.AuthProvider{
				LocationOfOrigin: "/path/to/kubeconfig",
				UserName:         "google",
				IDPIssuerURL:     "https://accounts.google.com",
				ClientID:         "YOUR_CLIENT_ID",
				ClientSecret:     "YOUR_CLIENT_SECRET",
				IDToken:          issuedIDToken,
				RefreshToken:     "YOUR_REFRESH_TOKEN",
			}).
			Return(xerrors.New("I/O error"))
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
			Return(&authentication.Output{
				TokenSet: oidc.TokenSet{
					IDToken:      issuedIDToken,
					RefreshToken: "YOUR_REFRESH_TOKEN",
				},
			}, nil)
		u := Standalone{
			Authentication: mockAuthentication,
			Kubeconfig:     mockKubeconfig,
			NewCertPool:    func() certpool.Interface { return mockCertPool },
			Logger:         logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
