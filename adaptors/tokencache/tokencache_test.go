package tokencache

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-test/deep"
	"github.com/int128/kubelogin/models/credentialplugin"
)

func TestRepository_Read(t *testing.T) {
	var r Repository

	t.Run("Success", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "kube")
		if err != nil {
			t.Fatalf("could not create a temp dir: %s", err)
		}
		defer func() {
			if err := os.RemoveAll(dir); err != nil {
				t.Errorf("could not clean up the temp dir: %s", err)
			}
		}()
		json := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}`
		filename := filepath.Join(dir, "token-cache")
		if err := ioutil.WriteFile(filename, []byte(json), 0600); err != nil {
			t.Fatalf("could not write to the temp file: %s", err)
		}

		tokenCache, err := r.Read(filename)
		if err != nil {
			t.Errorf("err wants nil but %+v", err)
		}
		want := &credentialplugin.TokenCache{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if diff := deep.Equal(tokenCache, want); diff != nil {
			t.Error(diff)
		}
	})
}

func TestRepository_Write(t *testing.T) {
	var r Repository

	t.Run("Success", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "kube")
		if err != nil {
			t.Fatalf("could not create a temp dir: %s", err)
		}
		defer func() {
			if err := os.RemoveAll(dir); err != nil {
				t.Errorf("could not clean up the temp dir: %s", err)
			}
		}()

		filename := filepath.Join(dir, "token-cache")
		tokenCache := credentialplugin.TokenCache{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if err := r.Write(filename, tokenCache); err != nil {
			t.Errorf("err wants nil but %+v", err)
		}

		b, err := ioutil.ReadFile(filename)
		if err != nil {
			t.Fatalf("could not read the token cache file: %s", err)
		}
		want := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}
`
		if diff := deep.Equal(string(b), want); diff != nil {
			t.Error(diff)
		}
	})
}
