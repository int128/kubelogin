package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/mocks/github.com/int128/kubelogin/pkg/oidc/client_mock"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/pkce"
	testingJWT "github.com/int128/kubelogin/pkg/testing/jwt"
	testingLogger "github.com/int128/kubelogin/pkg/testing/logger"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/clientcredentials"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/stretchr/testify/mock"
)

func TestAuthentication_Do(t *testing.T) {
	timeout := 5 * time.Second
	expiryTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	dummyProvider := oidc.Provider{
		IssuerURL:    "https://issuer.example.com",
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
	}
	dummyTLSClientConfig := tlsclientconfig.Config{
		CACertFilename: []string{"/path/to/cert"},
	}
	issuedIDToken := testingJWT.EncodeF(t, func(claims *testingJWT.Claims) {
		claims.Issuer = "https://accounts.google.com"
		claims.Subject = "YOUR_SUBJECT"
		claims.ExpiresAt = jwt.NewNumericDate(expiryTime)
	})

	t.Run("HasValidRefreshToken", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			Provider:        dummyProvider,
			TLSClientConfig: dummyTLSClientConfig,
			CachedTokenSet: &oidc.TokenSet{
				IDToken:      issuedIDToken,
				RefreshToken: "VALID_REFRESH_TOKEN",
			},
		}
		mockClient := client_mock.NewMockInterface(t)
		mockClient.EXPECT().
			Refresh(ctx, "VALID_REFRESH_TOKEN").
			Return(&oidc.TokenSet{
				IDToken:      "NEW_ID_TOKEN",
				RefreshToken: "NEW_REFRESH_TOKEN",
			}, nil)
		mockClientFactory := client_mock.NewMockFactoryInterface(t)
		mockClientFactory.EXPECT().
			New(ctx, dummyProvider, dummyTLSClientConfig).
			Return(mockClient, nil)
		u := Authentication{
			ClientFactory: mockClientFactory,
			Logger:        testingLogger.New(t),
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			TokenSet: oidc.TokenSet{
				IDToken:      "NEW_ID_TOKEN",
				RefreshToken: "NEW_REFRESH_TOKEN",
			},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("HasExpiredRefreshToken/Browser", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			Provider:        dummyProvider,
			TLSClientConfig: dummyTLSClientConfig,
			GrantOptionSet: GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:           []string{"127.0.0.1:8000"},
					SkipOpenBrowser:       true,
					AuthenticationTimeout: 10 * time.Second,
				},
			},
			CachedTokenSet: &oidc.TokenSet{
				IDToken:      issuedIDToken,
				RefreshToken: "EXPIRED_REFRESH_TOKEN",
			},
		}
		mockClient := client_mock.NewMockInterface(t)
		mockClient.EXPECT().NegotiatedPKCEMethod().Return(pkce.NoMethod)
		mockClient.EXPECT().
			Refresh(ctx, "EXPIRED_REFRESH_TOKEN").
			Return(nil, errors.New("token has expired"))
		mockClient.EXPECT().
			GetTokenByAuthCode(mock.Anything, mock.Anything, mock.Anything).
			Run(func(_ context.Context, _ client.GetTokenByAuthCodeInput, readyChan chan<- string) {
				readyChan <- "LOCAL_SERVER_URL"
			}).
			Return(&oidc.TokenSet{
				IDToken:      "NEW_ID_TOKEN",
				RefreshToken: "NEW_REFRESH_TOKEN",
			}, nil)
		mockClientFactory := client_mock.NewMockFactoryInterface(t)
		mockClientFactory.EXPECT().
			New(ctx, dummyProvider, dummyTLSClientConfig).
			Return(mockClient, nil)
		u := Authentication{
			ClientFactory: mockClientFactory,
			Logger:        testingLogger.New(t),
			AuthCodeBrowser: &authcode.Browser{
				Logger: testingLogger.New(t),
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			TokenSet: oidc.TokenSet{
				IDToken:      "NEW_ID_TOKEN",
				RefreshToken: "NEW_REFRESH_TOKEN",
			},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NoToken/ROPC", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		in := Input{
			Provider:        dummyProvider,
			TLSClientConfig: dummyTLSClientConfig,
			GrantOptionSet: GrantOptionSet{
				ROPCOption: &ropc.Option{
					Username: "USER",
					Password: "PASS",
				},
			},
		}
		mockClient := client_mock.NewMockInterface(t)
		mockClient.EXPECT().
			GetTokenByROPC(mock.Anything, "USER", "PASS").
			Return(&oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			}, nil)
		mockClientFactory := client_mock.NewMockFactoryInterface(t)
		mockClientFactory.EXPECT().
			New(ctx, dummyProvider, dummyTLSClientConfig).
			Return(mockClient, nil)
		u := Authentication{
			ClientFactory: mockClientFactory,
			Logger:        testingLogger.New(t),
			ROPC: &ropc.ROPC{
				Logger: testingLogger.New(t),
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			TokenSet: oidc.TokenSet{
				IDToken:      "YOUR_ID_TOKEN",
				RefreshToken: "YOUR_REFRESH_TOKEN",
			},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NoToken/ClientCredentials", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()
		ccIn := client.GetTokenByClientCredentialsInput{
			EndpointParams: map[string][]string{
				"audience": {"gopher://myaud"},
			},
		}
		in := Input{Provider: dummyProvider,
			TLSClientConfig: dummyTLSClientConfig,
			GrantOptionSet:  GrantOptionSet{ClientCredentialsOption: &ccIn}}
		testToken := &oidc.TokenSet{IDToken: "TEST_ID_TOKEN"}
		mockClient := client_mock.NewMockInterface(t)
		mockClient.EXPECT().
			GetTokenByClientCredentials(ctx, ccIn).Return(testToken, nil).Once()

		mockClientFactory := client_mock.NewMockFactoryInterface(t)
		mockClientFactory.EXPECT().
			New(ctx, dummyProvider, dummyTLSClientConfig).
			Return(mockClient, nil)
		u := Authentication{
			ClientFactory: mockClientFactory,
			Logger:        testingLogger.New(t),
			ClientCredentials: &clientcredentials.ClientCredentials{
				Logger: testingLogger.New(t),
			},
		}
		got, err := u.Do(ctx, in)
		if err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
		want := &Output{
			TokenSet: oidc.TokenSet{
				IDToken: "TEST_ID_TOKEN",
			},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestGrantOptionSet_AuthRequestExtraParams(t *testing.T) {
	t.Run("AuthCodeBrowserOption", func(t *testing.T) {
		gos := GrantOptionSet{
			AuthCodeBrowserOption: &authcode.BrowserOption{
				AuthRequestExtraParams: map[string]string{"audience": "api1", "foo": "bar"},
			},
		}
		got := gos.AuthRequestExtraParams()
		want := map[string]string{"audience": "api1", "foo": "bar"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("AuthCodeKeyboardOption", func(t *testing.T) {
		gos := GrantOptionSet{
			AuthCodeKeyboardOption: &authcode.KeyboardOption{
				AuthRequestExtraParams: map[string]string{"audience": "api2"},
			},
		}
		got := gos.AuthRequestExtraParams()
		want := map[string]string{"audience": "api2"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ClientCredentialsOption", func(t *testing.T) {
		gos := GrantOptionSet{
			ClientCredentialsOption: &client.GetTokenByClientCredentialsInput{
				EndpointParams: map[string][]string{
					"audience": {"api3"},
					"scope":    {"read", "write"},
				},
			},
		}
		got := gos.AuthRequestExtraParams()
		// Only the first value of each key is returned
		want := map[string]string{"audience": "api3", "scope": "read"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ROPCOption", func(t *testing.T) {
		gos := GrantOptionSet{
			ROPCOption: &ropc.Option{
				Username: "user",
				Password: "pass",
			},
		}
		got := gos.AuthRequestExtraParams()
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("NoOption", func(t *testing.T) {
		gos := GrantOptionSet{}
		got := gos.AuthRequestExtraParams()
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}
