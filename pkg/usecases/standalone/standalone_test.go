package standalone

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/int128/kubelogin/pkg/kubeconfig"
	"github.com/int128/kubelogin/pkg/kubeconfig/loader"
	"github.com/int128/kubelogin/pkg/kubeconfig/writer"
	"github.com/int128/kubelogin/pkg/oidc"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	"github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
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
		ctx := context.TODO()
		in := Input{
			KubeconfigFilename: "/path/to/kubeconfig",
			KubeconfigContext:  "theContext",
			KubeconfigUser:     "theUser",
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
		mockLoader := loader.NewMockInterface(t)
		mockLoader.EXPECT().
			GetCurrentAuthProvider("/path/to/kubeconfig", kubeconfig.ContextName("theContext"), kubeconfig.UserName("theUser")).
			Return(currentAuthProvider, nil)
		mockWriter := writer.NewMockInterface(t)
		mockWriter.EXPECT().
			UpdateAuthProvider(kubeconfig.AuthProvider{
				LocationOfOrigin:            "/path/to/kubeconfig",
				UserName:                    "theUser",
				IDPIssuerURL:                "https://accounts.google.com",
				ClientID:                    "YOUR_CLIENT_ID",
				ClientSecret:                "YOUR_CLIENT_SECRET",
				IDPCertificateAuthority:     "/path/to/cert2",
				IDPCertificateAuthorityData: "BASE64ENCODED2",
				IDToken:                     issuedIDToken,
				RefreshToken:                "YOUR_REFRESH_TOKEN",
			}).
			Return(nil)
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
				GrantOptionSet: grantOptionSet,
				TLSClientConfig: tlsclientconfig.Config{
					CACertFilename: []string{"/path/to/cert2"},
					CACertData:     []string{"BASE64ENCODED2"},
				},
			}).
			Return(&authentication.Output{
				TokenSet: oidc.TokenSet{
					IDToken:      issuedIDToken,
					RefreshToken: "YOUR_REFRESH_TOKEN",
				},
			}, nil)
		u := Standalone{
			Authentication:   mockAuthentication,
			KubeconfigLoader: mockLoader,
			KubeconfigWriter: mockWriter,
			Logger:           logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
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
		mockLoader := loader.NewMockInterface(t)
		mockLoader.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
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
		u := Standalone{
			Authentication:   mockAuthentication,
			KubeconfigLoader: mockLoader,
			Logger:           logger.New(t),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("NoOIDCConfig", func(t *testing.T) {
		ctx := context.TODO()
		in := Input{}
		mockLoader := loader.NewMockInterface(t)
		mockLoader.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(nil, errors.New("no oidc config"))
		mockAuthentication := authentication.NewMockInterface(t)
		u := Standalone{
			Authentication:   mockAuthentication,
			KubeconfigLoader: mockLoader,
			Logger:           logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		ctx := context.TODO()
		in := Input{}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "google",
			IDPIssuerURL:     "https://accounts.google.com",
			ClientID:         "YOUR_CLIENT_ID",
			ClientSecret:     "YOUR_CLIENT_SECRET",
		}
		mockLoader := loader.NewMockInterface(t)
		mockLoader.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
			}).
			Return(nil, errors.New("authentication error"))
		u := Standalone{
			Authentication:   mockAuthentication,
			KubeconfigLoader: mockLoader,
			Logger:           logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("WriteError", func(t *testing.T) {
		ctx := context.TODO()
		in := Input{}
		currentAuthProvider := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "google",
			IDPIssuerURL:     "https://accounts.google.com",
			ClientID:         "YOUR_CLIENT_ID",
			ClientSecret:     "YOUR_CLIENT_SECRET",
		}
		mockLoader := loader.NewMockInterface(t)
		mockLoader.EXPECT().
			GetCurrentAuthProvider("", kubeconfig.ContextName(""), kubeconfig.UserName("")).
			Return(currentAuthProvider, nil)
		mockWriter := writer.NewMockInterface(t)
		mockWriter.EXPECT().
			UpdateAuthProvider(kubeconfig.AuthProvider{
				LocationOfOrigin: "/path/to/kubeconfig",
				UserName:         "google",
				IDPIssuerURL:     "https://accounts.google.com",
				ClientID:         "YOUR_CLIENT_ID",
				ClientSecret:     "YOUR_CLIENT_SECRET",
				IDToken:          issuedIDToken,
				RefreshToken:     "YOUR_REFRESH_TOKEN",
			}).
			Return(errors.New("I/O error"))
		mockAuthentication := authentication.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
			}).
			Return(&authentication.Output{
				TokenSet: oidc.TokenSet{
					IDToken:      issuedIDToken,
					RefreshToken: "YOUR_REFRESH_TOKEN",
				},
			}, nil)
		u := Standalone{
			Authentication:   mockAuthentication,
			KubeconfigLoader: mockLoader,
			KubeconfigWriter: mockWriter,
			Logger:           logger.New(t),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}
