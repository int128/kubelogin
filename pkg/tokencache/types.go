package tokencache

// Key represents a key of a token cache.
type Key struct {
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	Username       string
	ExtraScopes    []string
	CACertFilename string
	CACertData     string
	SkipTLSVerify  bool
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
