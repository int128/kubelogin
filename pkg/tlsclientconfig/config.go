package tlsclientconfig

import "crypto/tls"

// Config represents a config for TLS client.
type Config struct {
	CACertFilename []string
	CACertData     []string
	SkipTLSVerify  bool
	Renegotiation  tls.RenegotiationSupport
}
