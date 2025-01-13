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
func New(t *testing.T, kp keypair.KeyPair, config testconfig.Config) service.Service {
	mux := http.NewServeMux()
	serverURL := startServer(t, mux, kp)

	svc := service.New(t, serverURL, config)
	handler.Register(t, mux, svc)
	return svc
}

func startServer(t *testing.T, h http.Handler, kp keypair.KeyPair) string {
	if kp == keypair.None {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		return srv.URL
	}

	// Unfortunately, httptest package did not work with keypair.KeyPair.
	// We use httptest package only for allocating a new port.
	portAllocator := httptest.NewUnstartedServer(h)
	t.Cleanup(portAllocator.Close)
	serverURL := fmt.Sprintf("https://localhost:%d", portAllocator.Listener.Addr().(*net.TCPAddr).Port)
	srv := &http.Server{Handler: h}
	go func() {
		err := srv.ServeTLS(portAllocator.Listener, kp.CertPath, kp.KeyPath)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	t.Cleanup(func() {
		if err := srv.Shutdown(context.TODO()); err != nil {
			t.Errorf("could not shutdown the server: %s", err)
		}
	})
	return serverURL
}
