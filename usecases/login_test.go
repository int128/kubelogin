package usecases

import (
	"context"
	"net/http"
	"testing"

	"github.com/coreos/go-oidc"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/int128/kubelogin/usecases/interfaces"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd/api"
)

func TestLogin_Do(t *testing.T) {
	httpClient := &http.Client{}

	newMockKubeConfig := func(ctrl *gomock.Controller, in *kubeconfig.KubeConfig, out *kubeconfig.KubeConfig) adaptors.KubeConfig {
		kubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		kubeConfig.EXPECT().
			LoadFromFile("/path/to/kubeconfig").
			Return(in, nil)
		kubeConfig.EXPECT().
			WriteToFile(out, "/path/to/kubeconfig")
		return kubeConfig
	}

	newMockHTTP := func(ctrl *gomock.Controller, config adaptors.HTTPClientConfig) adaptors.HTTP {
		mockHTTP := mock_adaptors.NewMockHTTP(ctrl)
		mockHTTP.EXPECT().
			NewClientConfig().
			Return(config)
		mockHTTP.EXPECT().
			NewClient(config).
			Return(httpClient, nil)
		return mockHTTP
	}

	newInConfig := func() *kubeconfig.KubeConfig {
		return &kubeconfig.KubeConfig{
			APIVersion:     "v1",
			CurrentContext: "default",
			Contexts: map[string]*api.Context{
				"default": {
					AuthInfo: "google",
					Cluster:  "example.k8s.local",
				},
				"another": {
					AuthInfo: "keycloak",
					Cluster:  "example.k8s.local",
				},
			},
			AuthInfos: map[string]*api.AuthInfo{
				"google": {
					AuthProvider: &api.AuthProviderConfig{
						Name: "oidc",
						Config: map[string]string{
							"client-id":      "YOUR_CLIENT_ID",
							"client-secret":  "YOUR_CLIENT_SECRET",
							"idp-issuer-url": "https://accounts.google.com",
						},
					},
				},
				"keycloak": {
					AuthProvider: &api.AuthProviderConfig{
						Name: "oidc",
						Config: map[string]string{
							"client-id":      "KEYCLOAK_CLIENT_ID",
							"client-secret":  "KEYCLOAK_CLIENT_SECRET",
							"idp-issuer-url": "https://keycloak.example.com",
						},
					},
				},
			},
		}
	}

	newOutConfig := func(in *kubeconfig.KubeConfig, user string) *kubeconfig.KubeConfig {
		config := in.DeepCopy()
		config.AuthInfos[user].AuthProvider.Config["id-token"] = "YOUR_ID_TOKEN"
		config.AuthInfos[user].AuthProvider.Config["refresh-token"] = "YOUR_REFRESH_TOKEN"
		return config
	}

	t.Run("Defaults", func(t *testing.T) {
		inConfig := newInConfig()
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Do(func(_ context.Context, _ adaptors.OIDCAuthenticateIn, cb adaptors.OIDCAuthenticateCallback) {
				cb.ShowLocalServerURL("http://localhost:10000")
			}).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeContextName", func(t *testing.T) {
		inConfig := newInConfig()
		outConfig := newOutConfig(inConfig, "keycloak")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://keycloak.example.com",
				ClientID:        "KEYCLOAK_CLIENT_ID",
				ClientSecret:    "KEYCLOAK_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			KubeContextName:    "another",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("SkipTLSVerify", func(t *testing.T) {
		inConfig := newInConfig()
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(true)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
			SkipTLSVerify:      true,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("SkipOpenBrowser", func(t *testing.T) {
		inConfig := newInConfig()
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
				SkipOpenBrowser: true,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
			SkipOpenBrowser:    true,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/ValidToken", func(t *testing.T) {
		inConfig := newInConfig()
		inConfig.AuthInfos["google"].AuthProvider.Config["id-token"] = "VALID"

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		kubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		kubeConfig.EXPECT().
			LoadFromFile("/path/to/kubeconfig").
			Return(inConfig, nil)

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			VerifyIDToken(ctx, adaptors.OIDCVerifyTokenIn{
				IDToken:  "VALID",
				Issuer:   "https://accounts.google.com",
				ClientID: "YOUR_CLIENT_ID",
				Client:   httpClient,
			}).
			Return(&oidc.IDToken{}, nil)

		u := Login{
			KubeConfig: kubeConfig,
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/InvalidToken", func(t *testing.T) {
		inConfig := newInConfig()
		inConfig.AuthInfos["google"].AuthProvider.Config["id-token"] = "EXPIRED"
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			VerifyIDToken(ctx, adaptors.OIDCVerifyTokenIn{
				IDToken:  "EXPIRED",
				Issuer:   "https://accounts.google.com",
				ClientID: "YOUR_CLIENT_ID",
				Client:   httpClient,
			}).
			Return(nil, errors.New("token is expired"))
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/extra-scopes", func(t *testing.T) {
		inConfig := newInConfig()
		inConfig.AuthInfos["google"].AuthProvider.Config["extra-scopes"] = "email,profile"
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{"email", "profile"},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/idp-certificate-authority", func(t *testing.T) {
		inConfig := newInConfig()
		inConfig.AuthInfos["google"].AuthProvider.Config["idp-certificate-authority"] = "/path/to/cert"
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)
		httpClientConfig.EXPECT().
			AddCertificateFromFile("/path/to/cert")

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/idp-certificate-authority/error", func(t *testing.T) {
		inConfig := newInConfig()
		inConfig.AuthInfos["google"].AuthProvider.Config["idp-certificate-authority"] = "/path/to/cert"
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)
		httpClientConfig.EXPECT().
			AddCertificateFromFile("/path/to/cert").
			Return(errors.New("not found"))

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/idp-certificate-authority-data", func(t *testing.T) {
		inConfig := newInConfig()
		inConfig.AuthInfos["google"].AuthProvider.Config["idp-certificate-authority-data"] = "base64encoded"
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)
		httpClientConfig.EXPECT().
			AddEncodedCertificate("base64encoded")

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/idp-certificate-authority-data/error", func(t *testing.T) {
		inConfig := newInConfig()
		inConfig.AuthInfos["google"].AuthProvider.Config["idp-certificate-authority-data"] = "base64encoded"
		outConfig := newOutConfig(inConfig, "google")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()

		httpClientConfig := mock_adaptors.NewMockHTTPClientConfig(ctrl)
		httpClientConfig.EXPECT().
			SetSkipTLSVerify(false)
		httpClientConfig.EXPECT().
			AddEncodedCertificate("base64encoded").
			Return(errors.New("invalid"))

		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			Authenticate(ctx, adaptors.OIDCAuthenticateIn{
				Issuer:          "https://accounts.google.com",
				ClientID:        "YOUR_CLIENT_ID",
				ClientSecret:    "YOUR_CLIENT_SECRET",
				ExtraScopes:     []string{},
				LocalServerPort: 10000,
				Client:          httpClient,
			}, gomock.Any()).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		u := Login{
			KubeConfig: newMockKubeConfig(ctrl, inConfig, outConfig),
			HTTP:       newMockHTTP(ctrl, httpClientConfig),
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         10000,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})
}
