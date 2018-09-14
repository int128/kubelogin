package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/int128/kubelogin/cli"
	"github.com/int128/kubelogin/e2e/authserver"
	"golang.org/x/sync/errgroup"
)

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
		serverConfig     authserver.Config
		clientTLS        *tls.Config
	}{
		"NoTLS": {
			kubeconfigValues{Issuer: "http://localhost:9000"},
			cli.CLI{},
			authserver.Config{Issuer: "http://localhost:9000"},
			&tls.Config{},
		},
		"ExtraScope": {
			kubeconfigValues{
				Issuer:      "http://localhost:9000",
				ExtraScopes: "profile groups",
			},
			cli.CLI{},
			authserver.Config{
				Issuer: "http://localhost:9000",
				Scope:  "profile groups openid",
			},
			&tls.Config{},
		},
		"SkipTLSVerify": {
			kubeconfigValues{Issuer: "https://localhost:9000"},
			cli.CLI{SkipTLSVerify: true},
			authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			&tls.Config{InsecureSkipVerify: true},
		},
		"CACert": {
			kubeconfigValues{
				Issuer:                  "https://localhost:9000",
				IDPCertificateAuthority: authserver.CACert,
			},
			cli.CLI{},
			authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			&tls.Config{RootCAs: readCert(t, authserver.CACert)},
		},
		"CACertData": {
			kubeconfigValues{
				Issuer: "https://localhost:9000",
				IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString(read(t, authserver.CACert)),
			},
			cli.CLI{},
			authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			&tls.Config{RootCAs: readCert(t, authserver.CACert)},
		},
	}

	for name, c := range data {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := c.serverConfig.Start(t)
			defer server.Shutdown(ctx)
			kubeconfig := createKubeconfig(t, &c.kubeconfigValues)
			defer os.Remove(kubeconfig)
			c.cli.KubeConfig = kubeconfig
			c.cli.SkipOpenBrowser = true
			c.cli.ListenPort = 8000

			var eg errgroup.Group
			eg.Go(func() error {
				return c.cli.Run(ctx)
			})
			if err := openBrowserRequest(c.clientTLS); err != nil {
				cancel()
				t.Error(err)
			}
			if err := eg.Wait(); err != nil {
				t.Fatalf("CLI returned error: %s", err)
			}
			verifyKubeconfig(t, kubeconfig)
		})
	}
}

func openBrowserRequest(tlsConfig *tls.Config) error {
	time.Sleep(50 * time.Millisecond)
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	res, err := client.Get("http://localhost:8000/")
	if err != nil {
		return fmt.Errorf("Could not send a request: %s", err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("StatusCode wants 200 but %d", res.StatusCode)
	}
	return nil
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
