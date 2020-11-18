package tlsclientconfig

import "crypto/tls"

// Config represents a config for TLS client.
type Config struct {
	// require omitempty for tokencache.Key
	CACertFilename []string                 `json:",omitempty"`
	CACertData     []string                 `json:",omitempty"`
	SkipTLSVerify  bool                     `json:",omitempty"`
	Renegotiation  tls.RenegotiationSupport `json:",omitempty"`
}
