package tls

import (
	"io/ioutil"
	"testing"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/e2e_test/logger"
	"github.com/int128/kubelogin/models/kubeconfig"
)

func TestNewConfig(t *testing.T) {
	testingLogger := logger.New(t)
	testingLogger.SetLevel(1)

	t.Run("Defaults", func(t *testing.T) {
		c, err := NewConfig(adaptors.OIDCClientConfig{}, testingLogger)
		if err != nil {
			t.Fatalf("NewConfig error: %+v", err)
		}
		if c.InsecureSkipVerify {
			t.Errorf("InsecureSkipVerify wants false but true")
		}
		if c.RootCAs != nil {
			t.Errorf("RootCAs wants nil but %+v", c.RootCAs)
		}
	})
	t.Run("SkipTLSVerify", func(t *testing.T) {
		config := adaptors.OIDCClientConfig{
			SkipTLSVerify: true,
		}
		c, err := NewConfig(config, testingLogger)
		if err != nil {
			t.Fatalf("NewConfig error: %+v", err)
		}
		if !c.InsecureSkipVerify {
			t.Errorf("InsecureSkipVerify wants true but false")
		}
		if c.RootCAs != nil {
			t.Errorf("RootCAs wants nil but %+v", c.RootCAs)
		}
	})
	t.Run("AllCertificates", func(t *testing.T) {
		config := adaptors.OIDCClientConfig{
			Config: kubeconfig.OIDCConfig{
				IDPCertificateAuthority:     "testdata/ca1.crt",
				IDPCertificateAuthorityData: string(readFile(t, "testdata/ca2.crt.base64")),
			},
			CACertFilename: "testdata/ca3.crt",
		}
		c, err := NewConfig(config, testingLogger)
		if err != nil {
			t.Fatalf("NewConfig error: %+v", err)
		}
		if c.InsecureSkipVerify {
			t.Errorf("InsecureSkipVerify wants false but true")
		}
		if c.RootCAs == nil {
			t.Fatalf("RootCAs wants non-nil but nil")
		}
		subjects := c.RootCAs.Subjects()
		if len(subjects) != 3 {
			t.Errorf("len(subjects) wants 3 but %d", len(subjects))
		}
	})
	t.Run("InvalidCertificate", func(t *testing.T) {
		config := adaptors.OIDCClientConfig{
			Config: kubeconfig.OIDCConfig{
				IDPCertificateAuthority:     "testdata/ca1.crt",
				IDPCertificateAuthorityData: string(readFile(t, "testdata/ca2.crt.base64")),
			},
			CACertFilename: "testdata/Makefile", // invalid cert
		}
		_, err := NewConfig(config, testingLogger)
		if err == nil {
			t.Fatalf("NewConfig wants non-nil but nil")
		}
		t.Logf("expected error: %+v", err)
	})
}

func readFile(t *testing.T, filename string) []byte {
	t.Helper()
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}
	return b
}
