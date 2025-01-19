package tokencache

import (
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
)

// Key represents a key of a token cache.
type Key struct {
	Provider        oidc.Provider
	TLSClientConfig tlsclientconfig.Config
	Username        string
}

// Config represents a configuration for the token cache.
type Config struct {
	// Directory is a path to the directory to store a token cache.
	// Note that a lock file is created into this directory even if the keyring is used.
	Directory string

	Storage Storage
}

// Storage is an enum of different storage strategies.
type Storage byte

const (
	// StorageAuto will prefer keyring when available, and fallback to disk when not.
	StorageAuto Storage = iota
	// StorageDisk will only store cached keys on disk.
	StorageDisk
	// StorageDisk will only store cached keys in the OS keyring.
	StorageKeyring
)
