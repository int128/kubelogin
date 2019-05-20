// Package authserver provides an authentication server which supports
// Authorization Code Grant and Resource Owner Password Credentials Grant.
// This is only for testing.
//
package authserver

import (
	"net/http"
	"testing"
)

// Config represents an authentication server configuration.
type Config struct {
	Addr          string
	TLSServerCert string
	TLSServerKey  string
	Handler       http.Handler
}

// Start starts an authentication server.
func Start(t *testing.T, c Config) *http.Server {
	s := &http.Server{
		Addr:    c.Addr,
		Handler: c.Handler,
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
