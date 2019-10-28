package certpool

import (
	"io/ioutil"
	"testing"
)

func TestCertPool_LoadFromFile(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		var f Factory
		p := f.New()
		if err := p.LoadFromFile("testdata/ca1.crt"); err != nil {
			t.Errorf("LoadFromFile error: %s", err)
		}
		n := len(p.GetX509CertPool().Subjects())
		if n != 1 {
			t.Errorf("n wants 1 but was %d", n)
		}
	})
	t.Run("Invalid", func(t *testing.T) {
		var f Factory
		p := f.New()
		err := p.LoadFromFile("testdata/Makefile")
		if err == nil {
			t.Errorf("LoadFromFile wants an error but was nil")
		}
	})
}

func TestCertPool_LoadBase64(t *testing.T) {
	var f Factory
	p := f.New()
	if err := p.LoadBase64(readFile(t, "testdata/ca2.crt.base64")); err != nil {
		t.Errorf("LoadBase64 error: %s", err)
	}
	n := len(p.GetX509CertPool().Subjects())
	if n != 1 {
		t.Errorf("n wants 1 but was %d", n)
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
