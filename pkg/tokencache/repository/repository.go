package repository

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/zalando/go-keyring"
)

// Set provides an implementation and interface for Kubeconfig.
var Set = wire.NewSet(
	wire.Struct(new(Repository), "*"),
	wire.Bind(new(Interface), new(*Repository)),
)

type Interface interface {
	FindByKey(dir string, storage tokencache.Storage, key tokencache.Key) (*oidc.TokenSet, error)
	Save(dir string, storage tokencache.Storage, key tokencache.Key, tokenSet oidc.TokenSet) error
	Lock(dir string, storage tokencache.Storage, key tokencache.Key) (io.Closer, error)
}

type entity struct {
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Repository provides access to the token cache on the local filesystem.
// Filename of a token cache is sha256 digest of the issuer, zero-character and client ID.
type Repository struct{}

// keyringService is used to namespace the keyring access.
// Some implementations may also display this string when prompting the user
// for allowing access.
const keyringService = "kubelogin"

// keyringItemPrefix is used as the prefix in the keyring items.
const keyringItemPrefix = "kubelogin/tokencache/"

func (r *Repository) FindByKey(dir string, storage tokencache.Storage, key tokencache.Key) (*oidc.TokenSet, error) {
	checksum, err := computeChecksum(key)
	if err != nil {
		return nil, fmt.Errorf("could not compute the key: %w", err)
	}
	switch storage {
	case tokencache.StorageAuto:
		t, err := readFromKeyring(checksum)
		if errors.Is(keyring.ErrUnsupportedPlatform, err) ||
			errors.Is(keyring.ErrNotFound, err) {
			return readFromFile(dir, checksum)
		}
		if err != nil {
			return nil, err
		}
		return t, nil
	case tokencache.StorageDisk:
		return readFromFile(dir, checksum)
	case tokencache.StorageKeyring:
		return readFromKeyring(checksum)
	default:
		return nil, fmt.Errorf("unknown storage mode: %v", storage)
	}
}

func readFromFile(dir, checksum string) (*oidc.TokenSet, error) {
	p := filepath.Join(dir, checksum)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %w", p, err)
	}
	t, err := decodeKey(b)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", p, err)
	}
	return t, nil
}

func readFromKeyring(checksum string) (*oidc.TokenSet, error) {
	p := keyringItemPrefix + checksum
	s, err := keyring.Get(keyringService, p)
	if err != nil {
		return nil, fmt.Errorf("could not get keyring secret %s: %w", p, err)
	}
	t, err := decodeKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("keyring %s: %w", p, err)
	}
	return t, nil
}

func decodeKey(b []byte) (*oidc.TokenSet, error) {
	var e entity
	err := json.Unmarshal(b, &e)
	if err != nil {
		return nil, fmt.Errorf("invalid token cache json: %w", err)
	}
	return &oidc.TokenSet{
		IDToken:      e.IDToken,
		RefreshToken: e.RefreshToken,
	}, nil
}

func (r *Repository) Save(dir string, storage tokencache.Storage, key tokencache.Key, tokenSet oidc.TokenSet) error {
	checksum, err := computeChecksum(key)
	if err != nil {
		return fmt.Errorf("could not compute the key: %w", err)
	}
	switch storage {
	case tokencache.StorageAuto:
		if err := writeToKeyring(checksum, tokenSet); err != nil {
			if errors.Is(keyring.ErrUnsupportedPlatform, err) {
				return writeToFile(dir, checksum, tokenSet)
			}
			return err
		}
		return nil
	case tokencache.StorageDisk:
		return writeToFile(dir, checksum, tokenSet)
	case tokencache.StorageKeyring:
		return writeToKeyring(checksum, tokenSet)
	default:
		return fmt.Errorf("unknown storage mode: %v", storage)
	}
}

func writeToFile(dir, checksum string, tokenSet oidc.TokenSet) error {
	p := filepath.Join(dir, checksum)
	b, err := encodeKey(tokenSet)
	if err != nil {
		return fmt.Errorf("file %s: %w", p, err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("could not create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		return fmt.Errorf("could not create file %s: %w", p, err)
	}
	return nil
}

func writeToKeyring(checksum string, tokenSet oidc.TokenSet) error {
	p := keyringItemPrefix + checksum
	b, err := encodeKey(tokenSet)
	if err != nil {
		return fmt.Errorf("keyring %s: %w", p, err)
	}
	if err := keyring.Set(keyringService, p, string(b)); err != nil {
		return fmt.Errorf("keyring write %s: %w", p, err)
	}
	return nil
}

func (r *Repository) Lock(tokenCacheDir string, storage tokencache.Storage, key tokencache.Key) (io.Closer, error) {
	checksum, err := computeChecksum(key)
	if err != nil {
		return nil, fmt.Errorf("could not compute the key: %w", err)
	}
	// NOTE: Both keyring and disk storage types use files for locking
	// No sensitive data is stored in the lock file
	return lockFile(tokenCacheDir, checksum)
}

func lockFile(tokenCacheDir, checksum string) (io.Closer, error) {
	if err := os.MkdirAll(tokenCacheDir, 0700); err != nil {
		return nil, fmt.Errorf("could not create directory %s: %w", tokenCacheDir, err)
	}
	// Do not lock the token cache file.
	// https://github.com/int128/kubelogin/issues/1144
	lockFilepath := filepath.Join(tokenCacheDir, checksum+".lock")
	lockFile := flock.New(lockFilepath)
	if err := lockFile.Lock(); err != nil {
		return nil, fmt.Errorf("could not lock the cache file %s: %w", lockFilepath, err)
	}
	return lockFile, nil
}

func encodeKey(tokenSet oidc.TokenSet) ([]byte, error) {
	e := entity{
		IDToken:      tokenSet.IDToken,
		RefreshToken: tokenSet.RefreshToken,
	}
	return json.Marshal(&e)
}

func computeChecksum(key tokencache.Key) (string, error) {
	s := sha256.New()
	e := gob.NewEncoder(s)
	if err := e.Encode(&key); err != nil {
		return "", fmt.Errorf("could not encode the key: %w", err)
	}
	h := hex.EncodeToString(s.Sum(nil))
	return h, nil
}
