package kubeconfig

import (
	"html/template"
	"io/ioutil"
	"strings"
	"testing"
)

// Values represents values in .kubeconfig template.
type Values struct {
	Issuer                      string
	ExtraScopes                 string
	IDPCertificateAuthority     string
	IDPCertificateAuthorityData string
}

// Create creates a kubeconfig file and returns path to it.
func Create(t *testing.T, v *Values) string {
	t.Helper()
	f, err := ioutil.TempFile("", "kubeconfig")
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
	return f.Name()
}

// Verify returns true if the kubeconfig has valid values.
func Verify(t *testing.T, kubeconfig string) {
	b, err := ioutil.ReadFile(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(b), "id-token: ey") == -1 {
		t.Errorf("kubeconfig wants id-token but %s", string(b))
	}
	if strings.Index(string(b), "refresh-token: 44df4c82-5ce7-4260-b54d-1da0d396ef2a") == -1 {
		t.Errorf("kubeconfig wants refresh-token but %s", string(b))
	}
}
