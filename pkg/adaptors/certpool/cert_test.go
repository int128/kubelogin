package certpool

import (
	"crypto/tls"
	"io/ioutil"
	"testing"
)

func TestCertPool_AddFile(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		var f Factory
		p := f.New()
		if err := p.AddFile("testdata/ca1.crt"); err != nil {
			t.Errorf("AddFile error: %s", err)
		}
		var cfg tls.Config
		p.SetRootCAs(&cfg)
		if n := len(cfg.RootCAs.Subjects()); n != 1 {
			t.Errorf("n wants 1 but was %d", n)
		}
	})
	t.Run("Invalid", func(t *testing.T) {
		var f Factory
		p := f.New()
		err := p.AddFile("testdata/Makefile")
		if err == nil {
			t.Errorf("AddFile wants an error but was nil")
		}
	})
}

func TestCertPool_AddBase64Encoded(t *testing.T) {
	var f Factory
	p := f.New()
	if err := p.AddBase64Encoded(readFile(t, "testdata/ca2.crt.base64")); err != nil {
		t.Errorf("AddBase64Encoded error: %s", err)
	}
	var cfg tls.Config
	p.SetRootCAs(&cfg)
	if n := len(cfg.RootCAs.Subjects()); n != 1 {
		t.Errorf("n wants 1 but was %d", n)
	}
}

func TestCertPool_SetRootCAs(t *testing.T) {
	var f Factory
	p := f.New()
	var cfg tls.Config
	p.SetRootCAs(&cfg)
	if cfg.RootCAs != nil {
		t.Errorf("cfg.RootCAs wants nil but was %+v", cfg.RootCAs)
	}
}

func readFile(t *testing.T, filename string) string {
	t.Helper()
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}
	return string(b)
}
