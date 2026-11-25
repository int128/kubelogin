package repository

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	FindByKey(config tokencache.Config, key tokencache.Key) (*oidc.TokenSet, error)
	Save(config tokencache.Config, key tokencache.Key, tokenSet oidc.TokenSet) error
	Lock(config tokencache.Config, key tokencache.Key) (io.Closer, error)
	DeleteAll(config tokencache.Config) error
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

// keyringEncryptionKeyPrefix marks a keyring item that holds the key of an encrypted token cache file.
// It is not JSON, so that older versions treat the item as a cache miss.
const keyringEncryptionKeyPrefix = "encryption-key:"

// encryptedFileSuffix is the suffix of a token cache file that is too large for the keyring.
const encryptedFileSuffix = ".encrypted"

// keyringSet is a variable to simulate the size limit of a keyring in tests.
var keyringSet = keyring.Set

func (r *Repository) FindByKey(config tokencache.Config, key tokencache.Key) (*oidc.TokenSet, error) {
	checksum, err := computeChecksum(key)
	if err != nil {
		return nil, fmt.Errorf("could not compute the key: %w", err)
	}
	switch config.Storage {
	case tokencache.StorageDisk:
		return readFromFile(config, checksum)
	case tokencache.StorageKeyring:
		return readFromKeyring(config, checksum)
	case tokencache.StorageNone:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown storage mode: %v", config.Storage)
	}
}

func readFromFile(config tokencache.Config, checksum string) (*oidc.TokenSet, error) {
	p := filepath.Join(config.Directory, checksum)
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

func readFromKeyring(config tokencache.Config, checksum string) (*oidc.TokenSet, error) {
	p := keyringItemPrefix + checksum
	s, err := keyring.Get(keyringService, p)
	if err != nil {
		return nil, fmt.Errorf("could not get keyring secret %s: %w", p, err)
	}
	if encodedKey, ok := strings.CutPrefix(s, keyringEncryptionKeyPrefix); ok {
		return readFromEncryptedFile(config, checksum, encodedKey)
	}
	t, err := decodeKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("keyring %s: %w", p, err)
	}
	return t, nil
}

func readFromEncryptedFile(config tokencache.Config, checksum, encodedKey string) (*oidc.TokenSet, error) {
	p := filepath.Join(config.Directory, checksum+encryptedFileSuffix)
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key in keyring %s: %w", keyringItemPrefix+checksum, err)
	}
	ciphertext, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %w", p, err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", p, err)
	}
	b, err := aead.Open(nil, nil, ciphertext, []byte(keyringItemPrefix+checksum))
	if err != nil {
		return nil, fmt.Errorf("could not decrypt file %s: %w", p, err)
	}
	t, err := decodeKey(b)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", p, err)
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

func (r *Repository) Save(config tokencache.Config, key tokencache.Key, tokenSet oidc.TokenSet) error {
	checksum, err := computeChecksum(key)
	if err != nil {
		return fmt.Errorf("could not compute the key: %w", err)
	}
	switch config.Storage {
	case tokencache.StorageDisk:
		return writeToFile(config, checksum, tokenSet)
	case tokencache.StorageKeyring:
		return writeToKeyring(config, checksum, tokenSet)
	case tokencache.StorageNone:
		return nil
	default:
		return fmt.Errorf("unknown storage mode: %v", config.Storage)
	}
}

func writeToFile(config tokencache.Config, checksum string, tokenSet oidc.TokenSet) error {
	p := filepath.Join(config.Directory, checksum)
	b, err := encodeKey(tokenSet)
	if err != nil {
		return fmt.Errorf("file %s: %w", p, err)
	}
	if err := os.MkdirAll(config.Directory, 0700); err != nil {
		return fmt.Errorf("could not create directory %s: %w", config.Directory, err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		return fmt.Errorf("could not create file %s: %w", p, err)
	}
	return nil
}

func writeToKeyring(config tokencache.Config, checksum string, tokenSet oidc.TokenSet) error {
	p := keyringItemPrefix + checksum
	b, err := encodeKey(tokenSet)
	if err != nil {
		return fmt.Errorf("keyring %s: %w", p, err)
	}
	err = keyringSet(keyringService, p, string(b))
	if errors.Is(err, keyring.ErrSetDataTooBig) {
		return writeToEncryptedFile(config, checksum, b)
	}
	if err != nil {
		return fmt.Errorf("keyring write %s: %w", p, err)
	}
	// Remove the encrypted file of a previous large token cache, if any.
	_ = os.Remove(filepath.Join(config.Directory, checksum+encryptedFileSuffix))
	return nil
}

// writeToEncryptedFile writes the token cache to a file encrypted with a new key,
// and stores the key in the keyring.
// This is used when the token cache is too large for the keyring,
// such as the macOS Keychain (about 3KB) or the Windows Credential Manager (2.5KB).
func writeToEncryptedFile(config tokencache.Config, checksum string, b []byte) error {
	p := filepath.Join(config.Directory, checksum+encryptedFileSuffix)
	item := keyringItemPrefix + checksum
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("could not generate an encryption key: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return fmt.Errorf("file %s: %w", p, err)
	}
	ciphertext := aead.Seal(nil, nil, b, []byte(item))
	if err := os.MkdirAll(config.Directory, 0700); err != nil {
		return fmt.Errorf("could not create directory %s: %w", config.Directory, err)
	}
	if err := os.WriteFile(p, ciphertext, 0600); err != nil {
		return fmt.Errorf("could not create file %s: %w", p, err)
	}
	encodedKey := keyringEncryptionKeyPrefix + base64.StdEncoding.EncodeToString(key)
	if err := keyringSet(keyringService, item, encodedKey); err != nil {
		return fmt.Errorf("keyring write %s: %w", item, err)
	}
	return nil
}

// newAEAD returns AES-256-GCM with a random nonce prepended to the ciphertext.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create a cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("could not create a cipher: %w", err)
	}
	return aead, nil
}

// Implement io.Closer for noneStorage type
type noneStorageCloser struct{}

func (c noneStorageCloser) Close() error { return nil }

func (r *Repository) Lock(config tokencache.Config, key tokencache.Key) (io.Closer, error) {
	if config.Storage == tokencache.StorageNone {
		return noneStorageCloser{}, nil
	}
	checksum, err := computeChecksum(key)
	if err != nil {
		return nil, fmt.Errorf("could not compute the key: %w", err)
	}
	// NOTE: Both keyring and disk storage types use files for locking
	// No sensitive data is stored in the lock file
	if err := os.MkdirAll(config.Directory, 0700); err != nil {
		return nil, fmt.Errorf("could not create directory %s: %w", config.Directory, err)
	}
	// Do not lock the token cache file.
	// https://github.com/int128/kubelogin/issues/1144
	lockFilepath := filepath.Join(config.Directory, checksum+".lock")
	lockFile := flock.New(lockFilepath)
	if err := lockFile.Lock(); err != nil {
		return nil, fmt.Errorf("could not lock the cache file %s: %w", lockFilepath, err)
	}
	return lockFile, nil
}

func (r *Repository) DeleteAll(config tokencache.Config) error {
	switch config.Storage {
	case tokencache.StorageDisk:
		if err := os.RemoveAll(config.Directory); err != nil {
			return fmt.Errorf("remove the directory %s: %w", config.Directory, err)
		}
		return nil
	case tokencache.StorageKeyring:
		if err := keyring.DeleteAll(keyringService); err != nil {
			return fmt.Errorf("keyring delete: %w", err)
		}
		return nil
	case tokencache.StorageNone:
		return nil
	default:
		return fmt.Errorf("unknown storage mode: %v", config.Storage)
	}
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
