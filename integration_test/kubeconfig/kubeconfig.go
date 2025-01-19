package kubeconfig

import (
	"html/template"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Values represents values in .kubeconfig template.
type Values struct {
	Issuer                      string
	ExtraScopes                 string
	IDPCertificateAuthority     string
	IDPCertificateAuthorityData string
	IDToken                     string
	RefreshToken                string
}

// Create creates a kubeconfig file and returns path to it.
func Create(t *testing.T, v *Values) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "kubeconfig")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tpl, err := template.ParseFiles("kubeconfig/testdata/kubeconfig.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Execute(f, v); err != nil {
		t.Fatal(err)
	}
	return name
}

type AuthProviderConfig struct {
	IDToken      string `yaml:"id-token"`
	RefreshToken string `yaml:"refresh-token"`
}

// Verify returns true if the kubeconfig has valid values.
func Verify(t *testing.T, kubeconfig string, want AuthProviderConfig) {
	t.Helper()
	f, err := os.Open(kubeconfig)
	if err != nil {
		t.Errorf("could not open kubeconfig: %s", err)
		return
	}
	defer f.Close()

	var y struct {
		Users []struct {
			User struct {
				AuthProvider struct {
					Config AuthProviderConfig `yaml:"config"`
				} `yaml:"auth-provider"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	d := yaml.NewDecoder(f)
	if err := d.Decode(&y); err != nil {
		t.Errorf("could not decode YAML: %s", err)
		return
	}
	if len(y.Users) != 1 {
		t.Errorf("len(users) wants 1 but %d", len(y.Users))
		return
	}
	currentConfig := y.Users[0].User.AuthProvider.Config
	if currentConfig.IDToken != want.IDToken {
		t.Errorf("id-token wants %s but %s", want.IDToken, currentConfig.IDToken)
	}
	if currentConfig.RefreshToken != want.RefreshToken {
		t.Errorf("refresh-token wants %s but %s", want.RefreshToken, currentConfig.RefreshToken)
	}
}
