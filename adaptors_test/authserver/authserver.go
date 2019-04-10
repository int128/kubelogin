package authserver

import (
	"crypto/rsa"
	"net/http"
	"testing"
)

// Config represents server configuration.
type Config struct {
	Issuer         string
	Scope          string
	TLSServerCert  string
	TLSServerKey   string
	IDToken        string
	RefreshToken   string
	IDTokenKeyPair *rsa.PrivateKey
}

// Start starts a HTTP server.
func Start(t *testing.T, c Config) *http.Server {
	s := &http.Server{
		Addr:    "localhost:9000",
		Handler: newHandler(t, c),
	}
	go func() {
		var err error
		if c.TLSServerCert != "" && c.TLSServerKey != "" {
			err = s.ListenAndServeTLS(c.TLSServerCert, c.TLSServerKey)
		} else {
			err = s.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	return s
}
