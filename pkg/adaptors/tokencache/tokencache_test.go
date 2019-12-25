package tokencache

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-test/deep"
)

func TestRepository_FindByKey(t *testing.T) {
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
		key := Key{
			IssuerURL:      "YOUR_ISSUER",
			ClientID:       "YOUR_CLIENT_ID",
			ClientSecret:   "YOUR_CLIENT_SECRET",
			ExtraScopes:    []string{"openid", "email"},
			CACertFilename: "/path/to/cert",
			SkipTLSVerify:  false,
		}
		json := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}`
		filename, err := computeFilename(key)
		if err != nil {
			t.Errorf("could not compute the key: %s", err)
		}
		p := filepath.Join(dir, filename)
		if err := ioutil.WriteFile(p, []byte(json), 0600); err != nil {
			t.Fatalf("could not write to the temp file: %s", err)
		}

		value, err := r.FindByKey(dir, key)
		if err != nil {
			t.Errorf("err wants nil but %+v", err)
		}
		want := &Value{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if diff := deep.Equal(value, want); diff != nil {
			t.Error(diff)
		}
	})
}

func TestRepository_Save(t *testing.T) {
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

		key := Key{
			IssuerURL:      "YOUR_ISSUER",
			ClientID:       "YOUR_CLIENT_ID",
			ClientSecret:   "YOUR_CLIENT_SECRET",
			ExtraScopes:    []string{"openid", "email"},
			CACertFilename: "/path/to/cert",
			SkipTLSVerify:  false,
		}
		value := Value{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if err := r.Save(dir, key, value); err != nil {
			t.Errorf("err wants nil but %+v", err)
		}

		filename, err := computeFilename(key)
		if err != nil {
			t.Errorf("could not compute the key: %s", err)
		}
		p := filepath.Join(dir, filename)
		b, err := ioutil.ReadFile(p)
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
