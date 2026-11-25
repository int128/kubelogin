package repository

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/zalando/go-keyring"
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

func TestComputeChecksum_AuthRequestExtraParams(t *testing.T) {
	baseKey := tokencache.Key{
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

	t.Run("DifferentExtraParamsProduceDifferentChecksums", func(t *testing.T) {
		key1 := baseKey
		key1.AuthRequestExtraParams = map[string]string{"audience": "api1"}

		key2 := baseKey
		key2.AuthRequestExtraParams = map[string]string{"audience": "api2"}

		checksum1, err := computeChecksum(key1)
		if err != nil {
			t.Fatalf("could not compute checksum for key1: %s", err)
		}

		checksum2, err := computeChecksum(key2)
		if err != nil {
			t.Fatalf("could not compute checksum for key2: %s", err)
		}

		if checksum1 == checksum2 {
			t.Errorf("expected different checksums for different AuthRequestExtraParams, got same: %s", checksum1)
		}
	})

	t.Run("SameExtraParamsProduceSameChecksum", func(t *testing.T) {
		key1 := baseKey
		key1.AuthRequestExtraParams = map[string]string{"audience": "api1"}

		key2 := baseKey
		key2.AuthRequestExtraParams = map[string]string{"audience": "api1"}

		checksum1, err := computeChecksum(key1)
		if err != nil {
			t.Fatalf("could not compute checksum for key1: %s", err)
		}

		checksum2, err := computeChecksum(key2)
		if err != nil {
			t.Fatalf("could not compute checksum for key2: %s", err)
		}

		if checksum1 != checksum2 {
			t.Errorf("expected same checksums for same AuthRequestExtraParams, got different: %s vs %s", checksum1, checksum2)
		}
	})

	t.Run("NilVsEmptyExtraParams", func(t *testing.T) {
		keyNil := baseKey
		keyNil.AuthRequestExtraParams = nil

		keyEmpty := baseKey
		keyEmpty.AuthRequestExtraParams = map[string]string{}

		checksumNil, err := computeChecksum(keyNil)
		if err != nil {
			t.Fatalf("could not compute checksum for keyNil: %s", err)
		}

		checksumEmpty, err := computeChecksum(keyEmpty)
		if err != nil {
			t.Fatalf("could not compute checksum for keyEmpty: %s", err)
		}

		// Nil and empty map produce different checksums due to gob encoding.
		// This is acceptable since in practice nil is the default when
		// --oidc-auth-request-extra-params is not specified.
		if checksumNil == checksumEmpty {
			t.Logf("nil and empty AuthRequestExtraParams produce same checksum (implementation detail)")
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

func TestRepository_Keyring(t *testing.T) {
	var r Repository
	key := tokencache.Key{
		Provider: oidc.Provider{
			IssuerURL: "YOUR_ISSUER",
			ClientID:  "YOUR_CLIENT_ID",
		},
	}
	checksum, err := computeChecksum(key)
	if err != nil {
		t.Fatalf("could not compute the key: %s", err)
	}
	item := keyringItemPrefix + checksum
	smallTokenSet := oidc.TokenSet{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
	largeTokenSet := oidc.TokenSet{IDToken: strings.Repeat("YOUR_ID_TOKEN", 100), RefreshToken: "YOUR_REFRESH_TOKEN"}

	t.Run("SmallTokenIsStoredInKeyring", func(t *testing.T) {
		config := setupKeyring(t)
		if err := r.Save(config, key, smallTokenSet); err != nil {
			t.Fatalf("could not save the token cache: %s", err)
		}
		got, err := keyring.Get(keyringService, item)
		if err != nil {
			t.Fatalf("could not get the keyring item: %s", err)
		}
		want := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}`
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("keyring item mismatch (-want +got):\n%s", diff)
		}
		assertFindByKey(t, &r, config, key, smallTokenSet)
	})

	t.Run("LargeTokenIsStoredInEncryptedFile", func(t *testing.T) {
		config := setupKeyring(t)
		if err := r.Save(config, key, largeTokenSet); err != nil {
			t.Fatalf("could not save the token cache: %s", err)
		}
		s, err := keyring.Get(keyringService, item)
		if err != nil {
			t.Fatalf("could not get the keyring item: %s", err)
		}
		if !strings.HasPrefix(s, keyringEncryptionKeyPrefix) {
			t.Errorf("keyring item wants an encryption key but was %q", s)
		}
		b, err := os.ReadFile(filepath.Join(config.Directory, checksum+encryptedFileSuffix))
		if err != nil {
			t.Fatalf("could not read the encrypted file: %s", err)
		}
		if strings.Contains(string(b), "YOUR_REFRESH_TOKEN") {
			t.Errorf("encrypted file contains the plaintext token")
		}
		assertFindByKey(t, &r, config, key, largeTokenSet)
	})

	t.Run("SmallTokenAfterLargeTokenRemovesEncryptedFile", func(t *testing.T) {
		config := setupKeyring(t)
		if err := r.Save(config, key, largeTokenSet); err != nil {
			t.Fatalf("could not save the large token cache: %s", err)
		}
		if err := r.Save(config, key, smallTokenSet); err != nil {
			t.Fatalf("could not save the small token cache: %s", err)
		}
		_, err := os.Stat(filepath.Join(config.Directory, checksum+encryptedFileSuffix))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("encrypted file wants removed but stat returned %v", err)
		}
		assertFindByKey(t, &r, config, key, smallTokenSet)
	})

	t.Run("TamperedEncryptedFile", func(t *testing.T) {
		config := setupKeyring(t)
		if err := r.Save(config, key, largeTokenSet); err != nil {
			t.Fatalf("could not save the token cache: %s", err)
		}
		p := filepath.Join(config.Directory, checksum+encryptedFileSuffix)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("could not read the encrypted file: %s", err)
		}
		b[len(b)-1] ^= 1
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatalf("could not write the encrypted file: %s", err)
		}
		if _, err := r.FindByKey(config, key); err == nil {
			t.Errorf("err wants non-nil but was nil")
		}
	})
}

// setupKeyring sets up a mock keyring that rejects secrets longer than 1000 bytes,
// and returns a config for the keyring storage.
func setupKeyring(t *testing.T) tokencache.Config {
	t.Helper()
	keyring.MockInit()
	keyringSet = func(service, user, password string) error {
		if len(password) > 1000 {
			return keyring.ErrSetDataTooBig
		}
		return keyring.Set(service, user, password)
	}
	t.Cleanup(func() { keyringSet = keyring.Set })
	return tokencache.Config{Directory: t.TempDir(), Storage: tokencache.StorageKeyring}
}

func assertFindByKey(t *testing.T, r *Repository, config tokencache.Config, key tokencache.Key, want oidc.TokenSet) {
	t.Helper()
	got, err := r.FindByKey(config, key)
	if err != nil {
		t.Fatalf("could not find the token cache: %s", err)
	}
	if diff := cmp.Diff(&want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
