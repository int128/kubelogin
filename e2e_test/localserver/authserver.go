// Package localserver provides a http server running on localhost.
// This is only for testing.
//
package localserver

import (
	"context"
	"net"
	"net/http"
	"testing"
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
func Start(t *testing.T, h http.Handler) (string, Shutdowner) {
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

// Start starts an authentication server with TLS.
func StartTLS(t *testing.T, cert string, key string, h http.Handler) (string, Shutdowner) {
	t.Helper()
	l, port := newLocalhostListener(t)
	url := "https://localhost:" + port
	s := &http.Server{
		Handler: h,
	}
	go func() {
		err := s.ServeTLS(l, cert, key)
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
