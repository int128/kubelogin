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
