package writer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/kubeconfig"
)

func TestKubeconfig_UpdateAuth(t *testing.T) {
	var w Writer

	t.Run("MinimumKeys", func(t *testing.T) {
		f := newKubeconfigFile(t)
		if err := w.UpdateAuthProvider(kubeconfig.AuthProvider{
			LocationOfOrigin: f,
			UserName:         "google",
			IDPIssuerURL:     "https://accounts.google.com",
			ClientID:         "GOOGLE_CLIENT_ID",
			ClientSecret:     "GOOGLE_CLIENT_SECRET",
			IDToken:          "YOUR_ID_TOKEN",
			RefreshToken:     "YOUR_REFRESH_TOKEN",
		}); err != nil {
			t.Fatalf("Could not update auth: %s", err)
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("Could not read kubeconfig: %s", err)
		}

		got := string(b)
		want := `apiVersion: v1
clusters: null
contexts: null
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
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("kubeconfig mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("FullKeys", func(t *testing.T) {
		f := newKubeconfigFile(t)
		if err := w.UpdateAuthProvider(kubeconfig.AuthProvider{
			LocationOfOrigin:            f,
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
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("Could not read kubeconfig: %s", err)
		}

		got := string(b)
		want := `apiVersion: v1
clusters: null
contexts: null
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
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("kubeconfig mismatch (-want +got):\n%s", diff)
		}
	})
}

const kubeconfigContent = `
apiVersion: v1
clusters: []
kind: Config
preferences: {}
users:
  - name: google
    user:
      auth-provider:
        config:
          idp-issuer-url: https://accounts.google.com
        name: oidc
`

func newKubeconfigFile(t *testing.T) string {
	f := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(f, []byte(kubeconfigContent), 0644); err != nil {
		t.Fatalf("Could not write kubeconfig: %s", err)
	}
	return f
}
