package cmd

import (
	"os"
	"path/filepath"

	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/spf13/pflag"
)

func getDefaultTokenCacheDir(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var defaultTokenCacheDir = filepath.Join(
	getDefaultTokenCacheDir("KUBECACHEDIR", filepath.Join("~", ".kube", "cache")),
	"oidc-login")

type tokenCacheOptions struct {
	TokenCacheDir string
	ForceKeyring  bool
	NoKeyring     bool
}

func (o *tokenCacheOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.TokenCacheDir, "token-cache-dir", defaultTokenCacheDir, "Path to a directory for token cache")
	f.BoolVar(&o.ForceKeyring, "force-keyring", false, "If set, cached tokens will be stored in the OS keyring")
	f.BoolVar(&o.NoKeyring, "no-keyring", false, "If set, cached tokens will be stored on disk")
}

func (o *tokenCacheOptions) expandHomedir() {
	o.TokenCacheDir = expandHomedir(o.TokenCacheDir)
}

func (o *tokenCacheOptions) tokenCacheConfig() tokencache.Config {
	tokenStorage := tokencache.StorageAuto
	switch {
	case o.ForceKeyring:
		tokenStorage = tokencache.StorageKeyring
	case o.NoKeyring:
		tokenStorage = tokencache.StorageDisk
	}
	return tokencache.Config{
		Directory: o.TokenCacheDir,
		Storage:   tokenStorage,
	}
}
