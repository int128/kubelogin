package repository

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tokencache"
)

func TestRepository_FindByKey(t *testing.T) {
	var r Repository

	t.Run("Success", func(t *testing.T) {
		dir := t.TempDir()
		config := tokencache.Config{
			Directory: dir,
			Storage:   tokencache.StorageDisk,
		}
		key := tokencache.Key{
			Provider: oidc.Provider{
				IssuerURL:    "YOUR_ISSUER",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				ExtraScopes:  []string{"openid", "email"},
			},
			TLSClientConfig: tlsclientconfig.Config{
				CACertFilename: []string{"/path/to/cert"},
			},
		}

		json := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}`
		filename, err := computeChecksum(key)
		if err != nil {
			t.Errorf("could not compute the key: %s", err)
		}
		p := filepath.Join(dir, filename)
		if err := os.WriteFile(p, []byte(json), 0600); err != nil {
			t.Fatalf("could not write to the temp file: %s", err)
		}

		got, err := r.FindByKey(config, key)
		if err != nil {
			t.Errorf("err wants nil but %+v", err)
		}
		want := &oidc.TokenSet{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestRepository_Save(t *testing.T) {
	var r Repository

	t.Run("Success", func(t *testing.T) {
		dir := t.TempDir()
		config := tokencache.Config{
			Directory: dir,
			Storage:   tokencache.StorageDisk,
		}
		key := tokencache.Key{
			Provider: oidc.Provider{
				IssuerURL:    "YOUR_ISSUER",
				ClientID:     "YOUR_CLIENT_ID",
				ClientSecret: "YOUR_CLIENT_SECRET",
				ExtraScopes:  []string{"openid", "email"},
			},
			TLSClientConfig: tlsclientconfig.Config{
				CACertFilename: []string{"/path/to/cert"},
			},
		}
		tokenSet := oidc.TokenSet{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if err := r.Save(config, key, tokenSet); err != nil {
			t.Errorf("err wants nil but %+v", err)
		}

		filename, err := computeChecksum(key)
		if err != nil {
			t.Errorf("could not compute the key: %s", err)
		}
		p := filepath.Join(dir, filename)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("could not read the token cache file: %s", err)
		}
		want := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}`
		got := string(b)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}
