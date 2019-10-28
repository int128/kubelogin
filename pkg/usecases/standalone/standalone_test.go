package standalone

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/pkg/adaptors/certpool/mock_certpool"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig/mock_kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/mock_authentication"
	"golang.org/x/xerrors"
)

func TestStandalone_Do(t *testing.T) {
	dummyTokenClaims := map[string]string{"sub": "YOUR_SUBJECT"}
	futureTime := time.Now().Add(time.Hour) //TODO: inject time service

	t.Run("FullOptions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		in := Input{
			KubeconfigFilename: "/path/to/kubeconfig",
			KubeconfigContext:  "theContext",
			KubeconfigUser:     "theUser",
			BindAddress:        []string{"127.0.0.1:8000"},
			SkipOpenBrowser:    true,
			Username:           "USER",
			Password:           "PASS",
			CACertFilename:     "/path/to/cert1",
			SkipTLSVerify:      true,
		}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin:            "/path/to/kubeconfig",
			UserName:                    "theUser",
			IDPIssuerURL:                "https://accounts.google.com",
			ClientID:                    "YOUR_CLIENT_ID",
			ClientSecret:                "YOUR_CLIENT_SECRET",
			IDPCertificateAuthority:     "/path/to/cert2",
			IDPCertificateAuthorityData: "BASE64ENCODED",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPool.EXPECT().
			LoadFromFile("/path/to/cert1")
		mockCertPool.EXPECT().
			LoadFromFile("/path/to/cert2")
		mockCertPool.EXPECT().
			LoadBase64("BASE64ENCODED")
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockCertPoolFactory.EXPECT().
			New().
			Return(mockCertPool)
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
				IDPCertificateAuthorityData: "BASE64ENCODED",
				IDToken:                     "YOUR_ID_TOKEN",
				RefreshToken:                "YOUR_REFRESH_TOKEN",
			})
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
		u := Standalone{
			Authentication:  mockAuthentication,
			Kubeconfig:      mockKubeconfig,
			CertPoolFactory: mockCertPoolFactory,
			Logger:          mock_logger.New(t),
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
			IDToken:          "VALID_ID_TOKEN",
		}
		mockCertPool := mock_certpool.NewMockInterface(ctrl)
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockCertPoolFactory.EXPECT().
			New().
			Return(mockCertPool)
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
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
		u := Standalone{
			Authentication:  mockAuthentication,
			Kubeconfig:      mockKubeconfig,
			CertPoolFactory: mockCertPoolFactory,
			Logger:          mock_logger.New(t),
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
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(nil, xerrors.New("no oidc config"))
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		u := Standalone{
			Authentication:  mockAuthentication,
			Kubeconfig:      mockKubeconfig,
			CertPoolFactory: mockCertPoolFactory,
			Logger:          mock_logger.New(t),
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
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockCertPoolFactory.EXPECT().
			New().
			Return(mockCertPool)
		mockKubeconfig := mock_kubeconfig.NewMockInterface(ctrl)
		mockKubeconfig.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				CertPool:     mockCertPool,
			}).
			Return(nil, xerrors.New("authentication error"))
		u := Standalone{
			Authentication:  mockAuthentication,
			Kubeconfig:      mockKubeconfig,
			CertPoolFactory: mockCertPoolFactory,
			Logger:          mock_logger.New(t),
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
		mockCertPoolFactory := mock_certpool.NewMockFactoryInterface(ctrl)
		mockCertPoolFactory.EXPECT().
			New().
			Return(mockCertPool)
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
				IDToken:          "YOUR_ID_TOKEN",
				RefreshToken:     "YOUR_REFRESH_TOKEN",
			}).
			Return(xerrors.New("I/O error"))
		mockAuthentication := mock_authentication.NewMockInterface(ctrl)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				CertPool:     mockCertPool,
			}).
			Return(&authentication.Output{
				IDToken:       "YOUR_ID_TOKEN",
				RefreshToken:  "YOUR_REFRESH_TOKEN",
				IDTokenExpiry: futureTime,
				IDTokenClaims: dummyTokenClaims,
			}, nil)
		u := Standalone{
			Authentication:  mockAuthentication,
			Kubeconfig:      mockKubeconfig,
			CertPoolFactory: mockCertPoolFactory,
			Logger:          mock_logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
