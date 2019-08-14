package tokencache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors"
	"github.com/int128/kubelogin/pkg/models/credentialplugin"
	"golang.org/x/xerrors"
)

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	wire.Struct(new(Repository), "*"),
	wire.Bind(new(adaptors.TokenCacheRepository), new(*Repository)),
)

// Repository provides access to the token cache on the local filesystem.
// Filename of a token cache is sha256 digest of the issuer, zero-character and client ID.
type Repository struct{}

func (r *Repository) FindByKey(dir string, key credentialplugin.TokenCacheKey) (*credentialplugin.TokenCache, error) {
	filename := filepath.Join(dir, computeFilename(key))
	f, err := os.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("could not open file %s: %w", filename, err)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	var c credentialplugin.TokenCache
	if err := d.Decode(&c); err != nil {
		return nil, xerrors.Errorf("could not decode json file %s: %w", filename, err)
	}
	return &c, nil
}

func (r *Repository) Save(dir string, key credentialplugin.TokenCacheKey, cache credentialplugin.TokenCache) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return xerrors.Errorf("could not create directory %s: %w", dir, err)
	}
	filename := filepath.Join(dir, computeFilename(key))
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return xerrors.Errorf("could not create file %s: %w", filename, err)
	}
	defer f.Close()
	e := json.NewEncoder(f)
	if err := e.Encode(&cache); err != nil {
		return xerrors.Errorf("could not encode json to file %s: %w", filename, err)
	}
	return nil
}

func computeFilename(key credentialplugin.TokenCacheKey) string {
	s := sha256.New()
	_, _ = s.Write([]byte(key.IssuerURL))
	_, _ = s.Write([]byte{0x00})
	_, _ = s.Write([]byte(key.ClientID))
	return hex.EncodeToString(s.Sum(nil))
}
