package credentialplugin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/credentialplugin/reader_mock"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/credentialplugin/writer_mock"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/tokencache/repository_mock"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/usecases/authentication_mock"
	"github.com/int128/kubelogin/mocks/io_mock"
	"github.com/int128/kubelogin/pkg/credentialplugin"
	"github.com/int128/kubelogin/pkg/testing/clock"
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
	expiryTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Local()
	issuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://accounts.google.com"
		claims.Subject = "YOUR_SUBJECT"
		claims.ExpiresAt = jwt.NewNumericDate(expiryTime)
	})
	issuedTokenSet := oidc.TokenSet{
		IDToken:      issuedIDToken,
		RefreshToken: "YOUR_REFRESH_TOKEN",
	}
	issuedOutput := credentialplugin.Output{
		Token:                          issuedIDToken,
		Expiry:                         expiryTime,
		ClientAuthenticationAPIVersion: "client.authentication.k8s.io/v1",
	}
	credentialpluginInput := credentialplugin.Input{
		ClientAuthenticationAPIVersion: "client.authentication.k8s.io/v1",
	}
	grantOptionSet := authentication.GrantOptionSet{
		AuthCodeBrowserOption: &authcode.BrowserOption{
			BindAddress: []string{"127.0.0.1:0"},
		},
	}

	t.Run("NoTokenCache", func(t *testing.T) {
		tokenCacheKey := tokencache.Key{
			Provider: oidc.Provider{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		ctx := context.TODO()
		in := Input{
			Provider: dummyProvider,
			TokenCacheConfig: tokencache.Config{
				Directory: "/path/to/token-cache",
			},
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication_mock.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{TokenSet: issuedTokenSet}, nil)
		mockCloser := io_mock.NewMockCloser(t)
		mockCloser.EXPECT().
			Close().
			Return(nil)
		mockRepository := repository_mock.NewMockInterface(t)
		mockRepository.EXPECT().
			Lock(in.TokenCacheConfig, tokenCacheKey).
			Return(mockCloser, nil)
		mockRepository.EXPECT().
			FindByKey(in.TokenCacheConfig, tokenCacheKey).
			Return(nil, errors.New("file not found"))
		mockRepository.EXPECT().
			Save(in.TokenCacheConfig, tokenCacheKey, issuedTokenSet).
			Return(nil)
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialpluginInput, nil)
		mockWriter := writer_mock.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		u := GetToken{
			Authentication:         mockAuthentication,
			TokenCacheRepository:   mockRepository,
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: mockWriter,
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("TokenCacheNoneReturnsNone", func(t *testing.T) {
		tokenCacheKey := tokencache.Key{
			Provider: oidc.Provider{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		ctx := context.TODO()
		in := Input{
			Provider: dummyProvider,
			TokenCacheConfig: tokencache.Config{
				Storage: tokencache.StorageNone,
			},
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication_mock.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{TokenSet: issuedTokenSet}, nil)
		mockCloser := io_mock.NewMockCloser(t)
		mockCloser.EXPECT().
			Close().
			Return(nil)
		mockRepository := repository_mock.NewMockInterface(t)
		mockRepository.EXPECT().
			Lock(in.TokenCacheConfig, tokenCacheKey).
			Return(mockCloser, nil)
		mockRepository.EXPECT().
			FindByKey(in.TokenCacheConfig, tokenCacheKey).
			Return(nil, nil)
		mockRepository.EXPECT().
			Save(in.TokenCacheConfig, tokenCacheKey, issuedTokenSet).
			Return(nil)
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialpluginInput, nil)
		mockWriter := writer_mock.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		u := GetToken{
			Authentication:         mockAuthentication,
			TokenCacheRepository:   mockRepository,
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: mockWriter,
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
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
			Provider: oidc.Provider{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
			Username: "YOUR_USERNAME",
		}

		ctx := context.TODO()
		in := Input{
			Provider: dummyProvider,
			TokenCacheConfig: tokencache.Config{
				Directory: "/path/to/token-cache",
			},
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication_mock.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(&authentication.Output{TokenSet: issuedTokenSet}, nil)
		mockCloser := io_mock.NewMockCloser(t)
		mockCloser.EXPECT().
			Close().
			Return(nil)
		mockRepository := repository_mock.NewMockInterface(t)
		mockRepository.EXPECT().
			Lock(in.TokenCacheConfig, tokenCacheKey).
			Return(mockCloser, nil)
		mockRepository.EXPECT().
			FindByKey(in.TokenCacheConfig, tokenCacheKey).
			Return(nil, errors.New("file not found"))
		mockRepository.EXPECT().
			Save(in.TokenCacheConfig, tokenCacheKey, issuedTokenSet).
			Return(nil)
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialplugin.Input{ClientAuthenticationAPIVersion: "client.authentication.k8s.io/v1"}, nil)
		mockWriter := writer_mock.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		u := GetToken{
			Authentication:         mockAuthentication,
			TokenCacheRepository:   mockRepository,
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: mockWriter,
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("HasValidIDToken", func(t *testing.T) {
		tokenCacheKey := tokencache.Key{
			Provider: oidc.Provider{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}

		ctx := context.TODO()
		in := Input{
			Provider: dummyProvider,
			TokenCacheConfig: tokencache.Config{
				Directory: "/path/to/token-cache",
			},
			GrantOptionSet: grantOptionSet,
		}
		mockCloser := io_mock.NewMockCloser(t)
		mockCloser.EXPECT().
			Close().
			Return(nil)
		mockRepository := repository_mock.NewMockInterface(t)
		mockRepository.EXPECT().
			Lock(in.TokenCacheConfig, tokenCacheKey).
			Return(mockCloser, nil)
		mockRepository.EXPECT().
			FindByKey(in.TokenCacheConfig, tokencache.Key{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
			}).
			Return(&issuedTokenSet, nil)
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialpluginInput, nil)
		mockWriter := writer_mock.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(issuedOutput).
			Return(nil)
		u := GetToken{
			Authentication:         authentication_mock.NewMockInterface(t),
			TokenCacheRepository:   mockRepository,
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: mockWriter,
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("AuthenticationError", func(t *testing.T) {
		tokenCacheKey := tokencache.Key{
			Provider: oidc.Provider{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
			},
		}
		ctx := context.TODO()
		in := Input{
			Provider: dummyProvider,
			TokenCacheConfig: tokencache.Config{
				Directory: "/path/to/token-cache",
			},
			GrantOptionSet: grantOptionSet,
		}
		mockAuthentication := authentication_mock.NewMockInterface(t)
		mockAuthentication.EXPECT().
			Do(ctx, authentication.Input{
				Provider:       dummyProvider,
				GrantOptionSet: grantOptionSet,
			}).
			Return(nil, errors.New("authentication error"))
		mockCloser := io_mock.NewMockCloser(t)
		mockCloser.EXPECT().
			Close().
			Return(nil)
		mockRepository := repository_mock.NewMockInterface(t)
		mockRepository.EXPECT().
			Lock(in.TokenCacheConfig, tokenCacheKey).
			Return(mockCloser, nil)
		mockRepository.EXPECT().
			FindByKey(in.TokenCacheConfig, tokencache.Key{
				Provider: oidc.Provider{
					IssuerURL:    "https://accounts.google.com",
					ClientID:     "YOUR_CLIENT_ID",
					ClientSecret: "YOUR_CLIENT_SECRET",
				},
			}).
			Return(nil, errors.New("file not found"))
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialpluginInput, nil)
		u := GetToken{
			Authentication:         mockAuthentication,
			TokenCacheRepository:   mockRepository,
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: writer_mock.NewMockInterface(t),
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		if err := u.Do(ctx, in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("ExecClientCertificate", func(t *testing.T) {
		tokenCacheKey := tokencache.Key{
			Provider: dummyProvider,
		}
		// The certificate expires before the token.
		certFile, keyFile, certPEM, keyPEM, notAfter := generateClientCertificate(t, expiryTime.Add(-30*time.Minute))
		ctx := context.TODO()
		in := Input{
			Provider: dummyProvider,
			TokenCacheConfig: tokencache.Config{
				Directory: "/path/to/token-cache",
			},
			GrantOptionSet:            grantOptionSet,
			ExecClientCertificateFile: certFile,
			ExecClientKeyFile:         keyFile,
		}
		mockCloser := io_mock.NewMockCloser(t)
		mockCloser.EXPECT().
			Close().
			Return(nil)
		mockRepository := repository_mock.NewMockInterface(t)
		mockRepository.EXPECT().
			Lock(in.TokenCacheConfig, tokenCacheKey).
			Return(mockCloser, nil)
		mockRepository.EXPECT().
			FindByKey(in.TokenCacheConfig, tokenCacheKey).
			Return(&issuedTokenSet, nil)
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialpluginInput, nil)
		mockWriter := writer_mock.NewMockInterface(t)
		mockWriter.EXPECT().
			Write(credentialplugin.Output{
				Token:                          issuedIDToken,
				Expiry:                         notAfter,
				ClientAuthenticationAPIVersion: "client.authentication.k8s.io/v1",
				ClientCertificateData:          certPEM,
				ClientKeyData:                  keyPEM,
			}).
			Return(nil)
		u := GetToken{
			Authentication:         authentication_mock.NewMockInterface(t),
			TokenCacheRepository:   mockRepository,
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: mockWriter,
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		if err := u.Do(ctx, in); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("ExecClientCertificateNotFound", func(t *testing.T) {
		in := Input{
			Provider:                  dummyProvider,
			ExecClientCertificateFile: filepath.Join(t.TempDir(), "client.crt"),
			ExecClientKeyFile:         filepath.Join(t.TempDir(), "client.key"),
		}
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialpluginInput, nil)
		u := GetToken{
			Authentication:         authentication_mock.NewMockInterface(t),
			TokenCacheRepository:   repository_mock.NewMockInterface(t),
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: writer_mock.NewMockInterface(t),
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		if err := u.Do(context.TODO(), in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})

	t.Run("ExecClientCertificateExpired", func(t *testing.T) {
		certFile, keyFile, _, _, _ := generateClientCertificate(t, expiryTime.Add(-2*time.Hour))
		in := Input{
			Provider:                  dummyProvider,
			ExecClientCertificateFile: certFile,
			ExecClientKeyFile:         keyFile,
		}
		mockReader := reader_mock.NewMockInterface(t)
		mockReader.EXPECT().
			Read().
			Return(credentialpluginInput, nil)
		u := GetToken{
			Authentication:         authentication_mock.NewMockInterface(t),
			TokenCacheRepository:   repository_mock.NewMockInterface(t),
			CredentialPluginReader: mockReader,
			CredentialPluginWriter: writer_mock.NewMockInterface(t),
			Logger:                 logger.New(t),
			Clock:                  clock.Fake(expiryTime.Add(-time.Hour)),
		}
		if err := u.Do(context.TODO(), in); err == nil {
			t.Errorf("err wants non-nil but nil")
		}
	})
}

// generateClientCertificate writes a self-signed certificate and key to a temporary directory.
// It returns the parsed NotAfter, because the certificate truncates it to seconds in UTC.
func generateClientCertificate(t *testing.T, notAfter time.Time) (certFile, keyFile, certPEM, keyPEM string, parsedNotAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %s", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %s", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	dir := t.TempDir()
	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, []byte(certPEM), 0600); err != nil {
		t.Fatalf("WriteFile: %s", err)
	}
	if err := os.WriteFile(keyFile, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("WriteFile: %s", err)
	}
	return certFile, keyFile, certPEM, keyPEM, cert.NotAfter
}
