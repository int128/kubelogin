// Package oidcserver provides a stub of OpenID Connect provider.
package oidcserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/int128/kubelogin/integration_test/keypair"
	"github.com/int128/kubelogin/integration_test/oidcserver/handler"
	"github.com/int128/kubelogin/integration_test/oidcserver/service"
	"github.com/int128/kubelogin/integration_test/oidcserver/testconfig"
)

// New starts a server for the OpenID Connect provider.
func New(t *testing.T, k keypair.KeyPair, c testconfig.TestConfig) service.Service {
	mux := http.NewServeMux()
	serverURL := startServer(t, mux, k)

	svc := service.New(t, serverURL, c)
	handler.Register(t, mux, svc)
	return svc
}

func startServer(t *testing.T, h http.Handler, k keypair.KeyPair) string {
	if k == keypair.None {
		sv := httptest.NewServer(h)
		t.Cleanup(sv.Close)
		return sv.URL
	}

	// Unfortunately, httptest package did not work with keypair.KeyPair.
	// We use httptest package only for allocating a new port.
	portAllocator := httptest.NewUnstartedServer(h)
	t.Cleanup(portAllocator.Close)
	serverURL := fmt.Sprintf("https://localhost:%d", portAllocator.Listener.Addr().(*net.TCPAddr).Port)
	sv := &http.Server{Handler: h}
	go func() {
		err := sv.ServeTLS(portAllocator.Listener, k.CertPath, k.KeyPath)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	t.Cleanup(func() {
		if err := sv.Shutdown(context.TODO()); err != nil {
			t.Errorf("could not shutdown the server: %s", err)
		}
	})
	return serverURL
}
