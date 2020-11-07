package loader

import (
	"io/ioutil"
	"testing"

	"github.com/int128/kubelogin/pkg/tlsclientconfig"
)

func TestLoader_Load(t *testing.T) {
	var loader Loader
	t.Run("Zero", func(t *testing.T) {
		cfg, err := loader.Load(tlsclientconfig.Config{})
		if err != nil {
			t.Errorf("Load error: %s", err)
		}
		if cfg.RootCAs != nil {
			t.Errorf("RootCAs wants nil but was %+v", cfg.RootCAs)
		}
	})
	t.Run("ValidFile", func(t *testing.T) {
		cfg, err := loader.Load(tlsclientconfig.Config{
			CACertFilename: []string{"testdata/ca1.crt"},
		})
		if err != nil {
			t.Errorf("Load error: %s", err)
		}
		if n := len(cfg.RootCAs.Subjects()); n != 1 {
			t.Errorf("n wants 1 but was %d", n)
		}
	})
	t.Run("InvalidFile", func(t *testing.T) {
		_, err := loader.Load(tlsclientconfig.Config{
			CACertFilename: []string{"testdata/Makefile"},
		})
		if err == nil {
			t.Errorf("AddFile wants an error but was nil")
		}
	})
	t.Run("ValidBase64", func(t *testing.T) {
		cfg, err := loader.Load(tlsclientconfig.Config{
			CACertData: []string{readFile(t, "testdata/ca2.crt.base64")},
		})
		if err != nil {
			t.Errorf("Load error: %s", err)
		}
		if n := len(cfg.RootCAs.Subjects()); n != 1 {
			t.Errorf("n wants 1 but was %d", n)
		}
	})
}

func readFile(t *testing.T, filename string) string {
	t.Helper()
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}
	return string(b)
}
