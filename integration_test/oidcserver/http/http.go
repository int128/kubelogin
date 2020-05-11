// Package http provides a http server running on localhost for testing.
package http

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
	s *http.Server
}

func (s *shutdowner) Shutdown(t *testing.T, ctx context.Context) {
	if err := s.s.Shutdown(ctx); err != nil {
		t.Errorf("could not shutdown the server: %s", err)
	}
}

func Start(t *testing.T, h http.Handler, k keypair.KeyPair) (string, Shutdowner) {
	if k == keypair.None {
		return startNoTLS(t, h)
	}
	return startTLS(t, h, k)
}

func startNoTLS(t *testing.T, h http.Handler) (string, *shutdowner) {
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
	return url, &shutdowner{s}
}

func startTLS(t *testing.T, h http.Handler, k keypair.KeyPair) (string, *shutdowner) {
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
	return url, &shutdowner{s}
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
