package oidc

import (
	"io/ioutil"
	"testing"

	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger/mock_logger"
)

func TestFactory_tlsConfigFor(t *testing.T) {
	testingLogger := mock_logger.New(t)
	factory := &Factory{Logger: testingLogger}

	t.Run("Defaults", func(t *testing.T) {
		c, err := factory.tlsConfigFor(ClientConfig{})
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
		config := ClientConfig{
			SkipTLSVerify: true,
		}
		c, err := factory.tlsConfigFor(config)
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
		config := ClientConfig{
			Config: kubeconfig.OIDCConfig{
				IDPCertificateAuthority:     "testdata/tls/ca1.crt",
				IDPCertificateAuthorityData: string(readFile(t, "testdata/tls/ca2.crt.base64")),
			},
			CACertFilename: "testdata/tls/ca3.crt",
		}
		c, err := factory.tlsConfigFor(config)
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
		config := ClientConfig{
			Config: kubeconfig.OIDCConfig{
				IDPCertificateAuthority:     "testdata/tls/ca1.crt",
				IDPCertificateAuthorityData: string(readFile(t, "testdata/tls/ca2.crt.base64")),
			},
			CACertFilename: "testdata/Makefile", // invalid cert
		}
		_, err := factory.tlsConfigFor(config)
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
