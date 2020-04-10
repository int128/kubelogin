// Package localserver provides a http server running on localhost.
// This is only for testing.
//
package localserver

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/int128/kubelogin/integration_test/keypair"
)

type Shutdowner interface {
	Shutdown(t *testing.T, ctx context.Context)
}

type shutdowner struct {
	l net.Listener
	s *http.Server
}

func (s *shutdowner) Shutdown(t *testing.T, ctx context.Context) {
	// s.Shutdown() closes the lister as well,
	// so we do not need to call l.Close() explicitly
	if err := s.s.Shutdown(ctx); err != nil {
		t.Errorf("Could not shutdown the server: %s", err)
	}
}

// Start starts an authentication server.
// If k is non-nil, it starts a TLS server.
func Start(t *testing.T, h http.Handler, k keypair.KeyPair) (string, Shutdowner) {
	if k == keypair.None {
		return startNoTLS(t, h)
	}
	return startTLS(t, h, k)
}

func startNoTLS(t *testing.T, h http.Handler) (string, Shutdowner) {
	t.Helper()
	l, port := newLocalhostListener(t)
	url := "http://localhost:" + port
	s := &http.Server{
		Handler: h,
	}
	go func() {
		err := s.Serve(l)
		if err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	return url, &shutdowner{l, s}
}

func startTLS(t *testing.T, h http.Handler, k keypair.KeyPair) (string, Shutdowner) {
	t.Helper()
	l, port := newLocalhostListener(t)
	url := "https://localhost:" + port
	s := &http.Server{
		Handler: h,
	}
	go func() {
		err := s.ServeTLS(l, k.CertPath, k.KeyPath)
		if err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	return url, &shutdowner{l, s}
}

func newLocalhostListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Could not create a listener: %s", err)
	}
	addr := l.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Could not parse the address %s: %s", addr, err)
	}
	return l, port
}
