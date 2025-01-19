package loader

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/kubeconfig"
	"k8s.io/client-go/tools/clientcmd/api"
)

func Test_loadByDefaultRules(t *testing.T) {
	t.Run("google.yaml>keycloak.yaml", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "testdata/kubeconfig.google.yaml"+string(os.PathListSeparator)+"testdata/kubeconfig.keycloak.yaml")

		config, err := loadByDefaultRules("")
		if err != nil {
			t.Fatalf("Could not load the configs: %s", err)
		}
		if w := "google@hello.k8s.local"; w != config.CurrentContext {
			t.Errorf("CurrentContext wants %s but %s", w, config.CurrentContext)
		}
		if _, ok := config.Contexts["google@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[google@hello.k8s.local] is missing")
		}
		if _, ok := config.Contexts["keycloak@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[keycloak@hello.k8s.local] is missing")
		}
		if _, ok := config.AuthInfos["google"]; !ok {
			t.Errorf("AuthInfos[google] is missing")
		}
		if _, ok := config.AuthInfos["keycloak"]; !ok {
			t.Errorf("AuthInfos[keycloak] is missing")
		}
	})

	t.Run("keycloak.yaml>google.yaml", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "testdata/kubeconfig.keycloak.yaml"+string(os.PathListSeparator)+"testdata/kubeconfig.google.yaml")

		config, err := loadByDefaultRules("")
		if err != nil {
			t.Fatalf("Could not load the configs: %s", err)
		}
		if w := "keycloak@hello.k8s.local"; w != config.CurrentContext {
			t.Errorf("CurrentContext wants %s but %s", w, config.CurrentContext)
		}
		if _, ok := config.Contexts["google@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[google@hello.k8s.local] is missing")
		}
		if _, ok := config.Contexts["keycloak@hello.k8s.local"]; !ok {
			t.Errorf("Contexts[keycloak@hello.k8s.local] is missing")
		}
		if _, ok := config.AuthInfos["google"]; !ok {
			t.Errorf("AuthInfos[google] is missing")
		}
		if _, ok := config.AuthInfos["keycloak"]; !ok {
			t.Errorf("AuthInfos[keycloak] is missing")
		}
	})
}

func Test_findCurrentAuthProvider(t *testing.T) {
	t.Run("CurrentContext", func(t *testing.T) {
		got, err := findCurrentAuthProvider(&api.Config{
			CurrentContext: "theContext",
			Contexts: map[string]*api.Context{
				"theContext": {
					AuthInfo: "theUser",
				},
			},
			AuthInfos: map[string]*api.AuthInfo{
				"theUser": {
					LocationOfOrigin: "/path/to/kubeconfig",
					AuthProvider: &api.AuthProviderConfig{
						Name: "oidc",
						Config: map[string]string{
							"idp-issuer-url":                 "https://accounts.google.com",
							"client-id":                      "GOOGLE_CLIENT_ID",
							"client-secret":                  "GOOGLE_CLIENT_SECRET",
							"idp-certificate-authority":      "/path/to/cert",
							"idp-certificate-authority-data": "BASE64",
							"extra-scopes":                   "email,profile",
							"id-token":                       "YOUR_ID_TOKEN",
							"refresh-token":                  "YOUR_REFRESH_TOKEN",
						},
					},
				},
			},
		}, "", "")
		if err != nil {
			t.Fatalf("Could not find the current auth: %s", err)
		}
		want := &kubeconfig.AuthProvider{
			LocationOfOrigin:            "/path/to/kubeconfig",
			UserName:                    "theUser",
			ContextName:                 "theContext",
			IDPIssuerURL:                "https://accounts.google.com",
			ClientID:                    "GOOGLE_CLIENT_ID",
			ClientSecret:                "GOOGLE_CLIENT_SECRET",
			IDPCertificateAuthority:     "/path/to/cert",
			IDPCertificateAuthorityData: "BASE64",
			ExtraScopes:                 []string{"email", "profile"},
			IDToken:                     "YOUR_ID_TOKEN",
			RefreshToken:                "YOUR_REFRESH_TOKEN",
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ByContextName", func(t *testing.T) {
		got, err := findCurrentAuthProvider(&api.Config{
			Contexts: map[string]*api.Context{
				"theContext": {
					AuthInfo: "theUser",
				},
			},
			AuthInfos: map[string]*api.AuthInfo{
				"theUser": {
					LocationOfOrigin: "/path/to/kubeconfig",
					AuthProvider: &api.AuthProviderConfig{
						Name: "oidc",
						Config: map[string]string{
							"idp-issuer-url": "https://accounts.google.com",
						},
					},
				},
			},
		}, "theContext", "")
		if err != nil {
			t.Fatalf("Could not find the current auth: %s", err)
		}
		want := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "theUser",
			ContextName:      "theContext",
			IDPIssuerURL:     "https://accounts.google.com",
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ByUserName", func(t *testing.T) {
		got, err := findCurrentAuthProvider(&api.Config{
			AuthInfos: map[string]*api.AuthInfo{
				"theUser": {
					LocationOfOrigin: "/path/to/kubeconfig",
					AuthProvider: &api.AuthProviderConfig{
						Name: "oidc",
						Config: map[string]string{
							"idp-issuer-url": "https://accounts.google.com",
						},
					},
				},
			},
		}, "", "theUser")
		if err != nil {
			t.Fatalf("Could not find the current auth: %s", err)
		}
		want := &kubeconfig.AuthProvider{
			LocationOfOrigin: "/path/to/kubeconfig",
			UserName:         "theUser",
			IDPIssuerURL:     "https://accounts.google.com",
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NoConfig", func(t *testing.T) {
		_, err := findCurrentAuthProvider(&api.Config{
			AuthInfos: map[string]*api.AuthInfo{
				"theUser": {
					LocationOfOrigin: "/path/to/kubeconfig",
					AuthProvider: &api.AuthProviderConfig{
						Name: "oidc",
					},
				},
			},
		}, "", "theUser")
		if err == nil {
			t.Fatalf("wants error but nil")
		}
	})

	t.Run("NotOIDC", func(t *testing.T) {
		_, err := findCurrentAuthProvider(&api.Config{
			AuthInfos: map[string]*api.AuthInfo{
				"theUser": {
					LocationOfOrigin: "/path/to/kubeconfig",
					AuthProvider: &api.AuthProviderConfig{
						Name:   "some",
						Config: map[string]string{"foo": "bar"},
					},
				},
			},
		}, "", "theUser")
		if err == nil {
			t.Fatalf("wants error but nil")
		}
	})
}
