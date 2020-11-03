package tlsclientconfig

// Config represents a config for TLS client.
type Config struct {
	CACertFilename []string
	CACertData     []string
	SkipTLSVerify  bool
}
