package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/spf13/pflag"
)

func getDefaultTokenCacheDir() string {
	// https://github.com/int128/kubelogin/pull/975
	if kubeCacheDir, ok := os.LookupEnv("KUBECACHEDIR"); ok {
		return filepath.Join(kubeCacheDir, "oidc-login")
	}
	return filepath.Join("~", ".kube", "cache", "oidc-login")
}

var allTokenCacheStorage = strings.Join([]string{"auto", "keyring", "disk"}, "|")

type tokenCacheOptions struct {
	TokenCacheDir     string
	TokenCacheStorage string
}

func (o *tokenCacheOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&o.TokenCacheDir, "token-cache-dir", getDefaultTokenCacheDir(), "Path to a directory of the token cache")
	f.StringVar(&o.TokenCacheStorage, "token-cache-storage", "auto", fmt.Sprintf("Storage for the token cache. One of (%s)", allTokenCacheStorage))
}

func (o *tokenCacheOptions) expandHomedir() {
	o.TokenCacheDir = expandHomedir(o.TokenCacheDir)
}

func (o *tokenCacheOptions) tokenCacheConfig() (tokencache.Config, error) {
	config := tokencache.Config{
		Directory: o.TokenCacheDir,
	}
	switch o.TokenCacheStorage {
	case "auto":
		config.Storage = tokencache.StorageAuto
	case "keyring":
		config.Storage = tokencache.StorageKeyring
	case "disk":
		config.Storage = tokencache.StorageDisk
	default:
		return tokencache.Config{}, fmt.Errorf("token-cache-storage must be one of (%s)", allTokenCacheStorage)
	}
	return config, nil
}
