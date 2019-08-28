package tokencache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/google/wire"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_tokencache/mock_tokencache.go github.com/int128/kubelogin/pkg/adaptors/tokencache Interface

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	wire.Struct(new(Repository), "*"),
	wire.Bind(new(Interface), new(*Repository)),
)

type Interface interface {
	FindByKey(dir string, key Key) (*TokenCache, error)
	Save(dir string, key Key, cache TokenCache) error
}

// Key represents a key of a token cache.
type Key struct {
	IssuerURL string
	ClientID  string
}

// TokenCache represents a token cache.
type TokenCache struct {
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Repository provides access to the token cache on the local filesystem.
// Filename of a token cache is sha256 digest of the issuer, zero-character and client ID.
type Repository struct{}

func (r *Repository) FindByKey(dir string, key Key) (*TokenCache, error) {
	filename := filepath.Join(dir, computeFilename(key))
	f, err := os.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("could not open file %s: %w", filename, err)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	var c TokenCache
	if err := d.Decode(&c); err != nil {
		return nil, xerrors.Errorf("could not decode json file %s: %w", filename, err)
	}
	return &c, nil
}

func (r *Repository) Save(dir string, key Key, cache TokenCache) error {
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

func computeFilename(key Key) string {
	s := sha256.New()
	_, _ = s.Write([]byte(key.IssuerURL))
	_, _ = s.Write([]byte{0x00})
	_, _ = s.Write([]byte(key.ClientID))
	return hex.EncodeToString(s.Sum(nil))
}
