package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/int128/kubelogin/cli"
	"golang.org/x/sync/errgroup"
)

const tlsCACert = "testdata/authserver-ca.crt"
const tlsServerCert = "testdata/authserver.crt"
const tlsServerKey = "testdata/authserver.key"

// End-to-end test.
//
// 1. Start the auth server at port 9000.
// 2. Run the CLI.
// 3. Open a request for port 8000.
// 4. Wait for the CLI.
// 5. Shutdown the auth server.
func TestE2E(t *testing.T) {
	data := map[string]struct {
		kubeconfigValues kubeconfigValues
		cli              cli.CLI
		startServer      func(*testing.T, http.Handler) *http.Server
		authClientTLS    *tls.Config
	}{
		"NoTLS": {
			kubeconfigValues{Issuer: "http://localhost:9000"},
			cli.CLI{},
			startServer,
			&tls.Config{},
		},
		"SkipTLSVerify": {
			kubeconfigValues{Issuer: "https://localhost:9000"},
			cli.CLI{SkipTLSVerify: true},
			startServerTLS,
			&tls.Config{InsecureSkipVerify: true},
		},
		"CACert": {
			kubeconfigValues{
				Issuer:                  "https://localhost:9000",
				IDPCertificateAuthority: tlsCACert,
			},
			cli.CLI{},
			startServerTLS,
			&tls.Config{RootCAs: readCert(t, tlsCACert)},
		},
		"CACertData": {
			kubeconfigValues{
				Issuer: "https://localhost:9000",
				IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString(read(t, tlsCACert)),
			},
			cli.CLI{},
			startServerTLS,
			&tls.Config{RootCAs: readCert(t, tlsCACert)},
		},
	}

	for name, c := range data {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			authServer := c.startServer(t, NewAuthHandler(t, c.kubeconfigValues.Issuer))
			defer authServer.Shutdown(ctx)
			kubeconfig := createKubeconfig(t, &c.kubeconfigValues)
			defer os.Remove(kubeconfig)
			c.cli.KubeConfig = kubeconfig
			c.cli.SkipOpenBrowser = true

			var eg errgroup.Group
			eg.Go(func() error {
				return c.cli.Run(ctx)
			})

			time.Sleep(50 * time.Millisecond)
			client := http.Client{Transport: &http.Transport{TLSClientConfig: c.authClientTLS}}
			res, err := client.Get("http://localhost:8000/")
			if err != nil {
				t.Fatalf("Could not send a request: %s", err)
			}
			if res.StatusCode != 200 {
				t.Fatalf("StatusCode wants 200 but %d", res.StatusCode)
			}

			if err := eg.Wait(); err != nil {
				t.Fatalf("CLI returned error: %s", err)
			}
			verifyKubeconfig(t, kubeconfig)
		})
	}
}

func startServer(t *testing.T, h http.Handler) *http.Server {
	s := &http.Server{
		Addr:    "localhost:9000",
		Handler: h,
	}
	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	return s
}

func startServerTLS(t *testing.T, h http.Handler) *http.Server {
	s := &http.Server{
		Addr:    "localhost:9000",
		Handler: h,
	}
	go func() {
		if err := s.ListenAndServeTLS(tlsServerCert, tlsServerKey); err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	return s
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatalf("Could not read %s: %s", name, err)
	}
	return b
}

func readCert(t *testing.T, name string) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	b := read(t, name)
	if !p.AppendCertsFromPEM(b) {
		t.Fatalf("Could not append cert from %s", name)
	}
	return p
}
