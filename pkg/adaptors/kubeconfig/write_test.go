package kubeconfig

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestKubeconfig_UpdateAuth(t *testing.T) {
	var k Kubeconfig

	t.Run("MinimumKeys", func(t *testing.T) {
		f := newKubeconfigFile(t)
		defer func() {
			if err := os.Remove(f.Name()); err != nil {
				t.Errorf("Could not remove the temp file: %s", err)
			}
		}()
		if err := k.UpdateAuthProvider(&AuthProvider{
			LocationOfOrigin: f.Name(),
			UserName:         "google",
			IDPIssuerURL:     "https://accounts.google.com",
			ClientID:         "GOOGLE_CLIENT_ID",
			ClientSecret:     "GOOGLE_CLIENT_SECRET",
			IDToken:          "YOUR_ID_TOKEN",
			RefreshToken:     "YOUR_REFRESH_TOKEN",
		}); err != nil {
			t.Fatalf("Could not update auth: %s", err)
		}
		b, err := ioutil.ReadFile(f.Name())
		if err != nil {
			t.Fatalf("Could not read kubeconfig: %s", err)
		}

		want := `apiVersion: v1
clusters: []
contexts: []
current-context: ""
kind: Config
preferences: {}
users:
- name: google
  user:
    auth-provider:
      config:
        client-id: GOOGLE_CLIENT_ID
        client-secret: GOOGLE_CLIENT_SECRET
        id-token: YOUR_ID_TOKEN
        idp-issuer-url: https://accounts.google.com
        refresh-token: YOUR_REFRESH_TOKEN
      name: oidc
`
		if want != string(b) {
			t.Errorf("---- kubeconfig wants ----\n%s\n---- but ----\n%s", want, string(b))
		}
	})

	t.Run("FullKeys", func(t *testing.T) {
		f := newKubeconfigFile(t)
		defer func() {
			if err := os.Remove(f.Name()); err != nil {
				t.Errorf("Could not remove the temp file: %s", err)
			}
		}()
		if err := k.UpdateAuthProvider(&AuthProvider{
			LocationOfOrigin:            f.Name(),
			UserName:                    "google",
			IDPIssuerURL:                "https://accounts.google.com",
			ClientID:                    "GOOGLE_CLIENT_ID",
			ClientSecret:                "GOOGLE_CLIENT_SECRET",
			IDPCertificateAuthority:     "/path/to/cert",
			IDPCertificateAuthorityData: "BASE64",
			ExtraScopes:                 []string{"email", "profile"},
			IDToken:                     "YOUR_ID_TOKEN",
			RefreshToken:                "YOUR_REFRESH_TOKEN",
		}); err != nil {
			t.Fatalf("Could not update auth: %s", err)
		}
		b, err := ioutil.ReadFile(f.Name())
		if err != nil {
			t.Fatalf("Could not read kubeconfig: %s", err)
		}

		want := `apiVersion: v1
clusters: []
contexts: []
current-context: ""
kind: Config
preferences: {}
users:
- name: google
  user:
    auth-provider:
      config:
        client-id: GOOGLE_CLIENT_ID
        client-secret: GOOGLE_CLIENT_SECRET
        extra-scopes: email,profile
        id-token: YOUR_ID_TOKEN
        idp-certificate-authority: /path/to/cert
        idp-certificate-authority-data: BASE64
        idp-issuer-url: https://accounts.google.com
        refresh-token: YOUR_REFRESH_TOKEN
      name: oidc
`
		if want != string(b) {
			t.Errorf("---- kubeconfig wants ----\n%s\n---- but ----\n%s", want, string(b))
		}
	})
}

func newKubeconfigFile(t *testing.T) *os.File {
	content := `apiVersion: v1
clusters: []
kind: Config
preferences: {}
users:
  - name: google
    user:
      auth-provider:
        config:
          idp-issuer-url: https://accounts.google.com
        name: oidc`
	f, err := ioutil.TempFile("", "kubeconfig")
	if err != nil {
		t.Fatalf("Could not create a file: %s", err)
	}
	defer f.Close()
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("Could not write kubeconfig: %s", err)
	}
	return f
}
