package login

import (
	"context"
	"testing"

	"github.com/coreos/go-oidc"
	"github.com/golang/mock/gomock"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/mock_adaptors"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/int128/kubelogin/usecases"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd/api"
)

type loginTestFixture struct {
	googleOIDCConfig            kubeconfig.OIDCConfig
	googleOIDCConfigWithToken   kubeconfig.OIDCConfig
	googleKubeConfig            *kubeconfig.Config
	googleKubeConfigWithToken   *kubeconfig.Config
	keycloakOIDCConfig          kubeconfig.OIDCConfig
	keycloakOIDCConfigWithToken kubeconfig.OIDCConfig
	keycloakKubeConfig          *kubeconfig.Config
	keycloakKubeConfigWithToken *kubeconfig.Config
	mergedKubeConfig            *kubeconfig.Config
}

func newLoginTestFixture() loginTestFixture {
	var f loginTestFixture
	f.googleOIDCConfig = kubeconfig.OIDCConfig{
		"client-id":      "GOOGLE_CLIENT_ID",
		"client-secret":  "GOOGLE_CLIENT_SECRET",
		"idp-issuer-url": "https://accounts.google.com",
	}
	f.googleKubeConfig = &kubeconfig.Config{
		APIVersion:     "v1",
		CurrentContext: "googleContext",
		Contexts: map[string]*api.Context{
			"googleContext": {
				LocationOfOrigin: "/path/to/google",
				AuthInfo:         "google",
				Cluster:          "example.k8s.local",
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			"google": {
				LocationOfOrigin: "/path/to/google",
				AuthProvider: &api.AuthProviderConfig{
					Name:   "oidc",
					Config: f.googleOIDCConfig,
				},
			},
		},
	}
	f.googleOIDCConfigWithToken = kubeconfig.OIDCConfig{
		"client-id":      "GOOGLE_CLIENT_ID",
		"client-secret":  "GOOGLE_CLIENT_SECRET",
		"idp-issuer-url": "https://accounts.google.com",
		"id-token":       "YOUR_ID_TOKEN",
		"refresh-token":  "YOUR_REFRESH_TOKEN",
	}
	f.googleKubeConfigWithToken = &kubeconfig.Config{
		APIVersion:     "v1",
		CurrentContext: "googleContext",
		Contexts: map[string]*api.Context{
			"googleContext": {
				LocationOfOrigin: "/path/to/google",
				AuthInfo:         "google",
				Cluster:          "example.k8s.local",
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			"google": {
				LocationOfOrigin: "/path/to/google",
				AuthProvider: &api.AuthProviderConfig{
					Name:   "oidc",
					Config: f.googleOIDCConfigWithToken,
				},
			},
		},
	}

	f.keycloakOIDCConfig = kubeconfig.OIDCConfig{
		"client-id":      "KEYCLOAK_CLIENT_ID",
		"client-secret":  "KEYCLOAK_CLIENT_SECRET",
		"idp-issuer-url": "https://keycloak.example.com",
	}
	f.keycloakKubeConfig = &kubeconfig.Config{
		APIVersion:     "v1",
		CurrentContext: "googleContext",
		Contexts: map[string]*api.Context{
			"keycloakContext": {
				LocationOfOrigin: "/path/to/keycloak",
				AuthInfo:         "keycloak",
				Cluster:          "example.k8s.local",
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			"keycloak": {
				LocationOfOrigin: "/path/to/keycloak",
				AuthProvider: &api.AuthProviderConfig{
					Name:   "oidc",
					Config: f.keycloakOIDCConfig,
				},
			},
		},
	}
	f.keycloakOIDCConfigWithToken = kubeconfig.OIDCConfig{
		"client-id":      "KEYCLOAK_CLIENT_ID",
		"client-secret":  "KEYCLOAK_CLIENT_SECRET",
		"idp-issuer-url": "https://keycloak.example.com",
		"id-token":       "YOUR_ID_TOKEN",
		"refresh-token":  "YOUR_REFRESH_TOKEN",
	}
	f.keycloakKubeConfigWithToken = &kubeconfig.Config{
		APIVersion:     "v1",
		CurrentContext: "googleContext",
		Contexts: map[string]*api.Context{
			"keycloakContext": {
				LocationOfOrigin: "/path/to/keycloak",
				AuthInfo:         "keycloak",
				Cluster:          "example.k8s.local",
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			"keycloak": {
				LocationOfOrigin: "/path/to/keycloak",
				AuthProvider: &api.AuthProviderConfig{
					Name:   "oidc",
					Config: f.keycloakOIDCConfigWithToken,
				},
			},
		},
	}

	f.mergedKubeConfig = &kubeconfig.Config{
		APIVersion:     "v1",
		CurrentContext: "googleContext",
		Contexts: map[string]*api.Context{
			"googleContext": {
				LocationOfOrigin: "/path/to/google",
				AuthInfo:         "google",
				Cluster:          "example.k8s.local",
			},
			"keycloakContext": {
				LocationOfOrigin: "/path/to/keycloak",
				AuthInfo:         "keycloak",
				Cluster:          "example.k8s.local",
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			"google": {
				LocationOfOrigin: "/path/to/google",
				AuthProvider: &api.AuthProviderConfig{
					Name:   "oidc",
					Config: f.googleOIDCConfig,
				},
			},
			"keycloak": {
				LocationOfOrigin: "/path/to/keycloak",
				AuthProvider: &api.AuthProviderConfig{
					Name:   "oidc",
					Config: f.keycloakOIDCConfig,
				},
			},
		},
	}
	return f
}

type mockPrompt struct{}

func (*mockPrompt) ShowLocalServerURL(url string) {
	panic("do not call")
}

func TestLogin_Do(t *testing.T) {
	var prompt mockPrompt

	newMockOIDC := func(ctrl *gomock.Controller, config adaptors.HTTPClientConfig, client adaptors.OIDCClient) *mock_adaptors.MockOIDC {
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			NewClient(config).
			Return(client, nil)
		return mockOIDC
	}

	newMockCodeOIDC := func(ctrl *gomock.Controller, ctx context.Context, in adaptors.OIDCAuthenticateByCodeIn) *mock_adaptors.MockOIDCClient {
		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByCode(ctx, in).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)
		return mockOIDCClient
	}

	t.Run("Defaults", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/google").
			Return(f.googleKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.googleKubeConfigWithToken, "/path/to/google")

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig: f.googleOIDCConfig,
		}, newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.googleOIDCConfig,
			LocalServerPort: []int{10000},
			Prompt:          &prompt,
		}))

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort: []int{10000},
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("ResourceOwnerPasswordCredentials", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/google").
			Return(f.googleKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.googleKubeConfigWithToken, "/path/to/google")

		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			AuthenticateByPassword(ctx, adaptors.OIDCAuthenticateByPasswordIn{
				Config:   f.googleOIDCConfig,
				Username: "USER",
				Password: "PASS",
			}).
			Return(&adaptors.OIDCAuthenticateOut{
				VerifiedIDToken: &oidc.IDToken{Subject: "SUBJECT"},
				IDToken:         "YOUR_ID_TOKEN",
				RefreshToken:    "YOUR_REFRESH_TOKEN",
			}, nil)

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig: f.googleOIDCConfig,
		}, mockOIDCClient)

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort: []int{10000},
			Username:   "USER",
			Password:   "PASS",
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfigFilename", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("/path/to/kubeconfig").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/google").
			Return(f.googleKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.googleKubeConfigWithToken, "/path/to/google")

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig: f.googleOIDCConfig,
		}, newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.googleOIDCConfig,
			LocalServerPort: []int{10000},
			Prompt:          &prompt,
		}))

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeConfigFilename: "/path/to/kubeconfig",
			ListenPort:         []int{10000},
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeContextName", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/keycloak").
			Return(f.keycloakKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.keycloakKubeConfigWithToken, "/path/to/keycloak")

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig: f.keycloakOIDCConfig,
		}, newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.keycloakOIDCConfig,
			LocalServerPort: []int{10000},
			Prompt:          &prompt,
		}))

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeContextName: "keycloakContext",
			ListenPort:      []int{10000},
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeUserName", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/keycloak").
			Return(f.keycloakKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.keycloakKubeConfigWithToken, "/path/to/keycloak")

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig: f.keycloakOIDCConfig,
		}, newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.keycloakOIDCConfig,
			LocalServerPort: []int{10000},
			Prompt:          &prompt,
		}))

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			KubeUserName: "keycloak",
			ListenPort:   []int{10000},
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("SkipTLSVerify", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/google").
			Return(f.googleKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.googleKubeConfigWithToken, "/path/to/google")

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig:    f.googleOIDCConfig,
			SkipTLSVerify: true,
		}, newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.googleOIDCConfig,
			LocalServerPort: []int{10000},
			Prompt:          &prompt,
		}))

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort:    []int{10000},
			SkipTLSVerify: true,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("SkipOpenBrowser", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/google").
			Return(f.googleKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.googleKubeConfigWithToken, "/path/to/google")

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig: f.googleOIDCConfig,
		}, newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.googleOIDCConfig,
			LocalServerPort: []int{10000},
			SkipOpenBrowser: true,
			Prompt:          &prompt,
		}))

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort:      []int{10000},
			SkipOpenBrowser: true,
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/ValidToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()
		f.googleOIDCConfig.SetIDToken("VALID_TOKEN")

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)

		mockOIDCClient := mock_adaptors.NewMockOIDCClient(ctrl)
		mockOIDCClient.EXPECT().
			Verify(ctx, adaptors.OIDCVerifyIn{
				Config: f.googleOIDCConfig,
			}).
			Return(&oidc.IDToken{}, nil)
		mockOIDC := mock_adaptors.NewMockOIDC(ctrl)
		mockOIDC.EXPECT().
			NewClient(adaptors.HTTPClientConfig{
				OIDCConfig: f.googleOIDCConfig,
			}).
			Return(mockOIDCClient, nil)

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort: []int{10000},
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("KubeConfig/InvalidToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()
		f.googleOIDCConfig.SetIDToken("EXPIRED_TOKEN")

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/google").
			Return(f.googleKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.googleKubeConfigWithToken, "/path/to/google")

		mockOIDCClient := newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.googleOIDCConfig,
			LocalServerPort: []int{10000},
			Prompt:          &prompt,
		})
		mockOIDCClient.EXPECT().
			Verify(ctx, adaptors.OIDCVerifyIn{
				Config: f.googleOIDCConfig,
			}).
			Return(nil, errors.New("token is expired"))
		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig: f.googleOIDCConfig,
		}, mockOIDCClient)

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort: []int{10000},
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})

	t.Run("Certificates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.TODO()
		f := newLoginTestFixture()
		f.googleOIDCConfig["idp-certificate-authority"] = "/path/to/cert2"
		f.googleOIDCConfig["idp-certificate-authority-data"] = "base64encoded"
		f.googleOIDCConfigWithToken["idp-certificate-authority"] = "/path/to/cert2"
		f.googleOIDCConfigWithToken["idp-certificate-authority-data"] = "base64encoded"

		mockKubeConfig := mock_adaptors.NewMockKubeConfig(ctrl)
		mockKubeConfig.EXPECT().
			LoadByDefaultRules("").
			Return(f.mergedKubeConfig, nil)
		mockKubeConfig.EXPECT().
			LoadFromFile("/path/to/google").
			Return(f.googleKubeConfig, nil)
		mockKubeConfig.EXPECT().
			WriteToFile(f.googleKubeConfigWithToken, "/path/to/google")

		mockOIDC := newMockOIDC(ctrl, adaptors.HTTPClientConfig{
			OIDCConfig:                   f.googleOIDCConfig,
			CertificateAuthorityFilename: "/path/to/cert1",
		}, newMockCodeOIDC(ctrl, ctx, adaptors.OIDCAuthenticateByCodeIn{
			Config:          f.googleOIDCConfig,
			LocalServerPort: []int{10000},
			Prompt:          &prompt,
		}))

		u := Login{
			KubeConfig: mockKubeConfig,
			OIDC:       mockOIDC,
			Logger:     mock_adaptors.NewLogger(t, ctrl),
			Prompt:     &prompt,
		}
		if err := u.Do(ctx, usecases.LoginIn{
			ListenPort:                   []int{10000},
			CertificateAuthorityFilename: "/path/to/cert1",
		}); err != nil {
			t.Errorf("Do returned error: %+v", err)
		}
	})
}
