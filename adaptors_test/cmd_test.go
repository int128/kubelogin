package adaptors_test

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

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/adaptors_test/authserver"
	"github.com/int128/kubelogin/adaptors_test/kubeconfig"
	"github.com/int128/kubelogin/di"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// End-to-end test.
//
// 1. Start the auth server at port 9000.
// 2. Run the CLI.
// 3. Open a request for port 8000.
// 4. Wait for the CLI.
// 5. Shutdown the auth server.
//
func TestCmd_Run(t *testing.T) {
	data := map[string]struct {
		kubeconfigValues kubeconfig.Values
		args             []string
		serverConfig     authserver.Config
		clientTLS        *tls.Config
	}{
		"NoTLS": {
			kubeconfig.Values{Issuer: "http://localhost:9000"},
			[]string{"kubelogin"},
			authserver.Config{Issuer: "http://localhost:9000"},
			&tls.Config{},
		},
		"ExtraScope": {
			kubeconfig.Values{
				Issuer:      "http://localhost:9000",
				ExtraScopes: "profile groups",
			},
			[]string{"kubelogin"},
			authserver.Config{
				Issuer: "http://localhost:9000",
				Scope:  "profile groups openid",
			},
			&tls.Config{},
		},
		"SkipTLSVerify": {
			kubeconfig.Values{Issuer: "https://localhost:9000"},
			[]string{"kubelogin", "--insecure-skip-tls-verify"},
			authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			&tls.Config{InsecureSkipVerify: true},
		},
		"CACert": {
			kubeconfig.Values{
				Issuer:                  "https://localhost:9000",
				IDPCertificateAuthority: authserver.CACert,
			},
			[]string{"kubelogin"},
			authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			&tls.Config{RootCAs: readCert(t, authserver.CACert)},
		},
		"CACertData": {
			kubeconfig.Values{
				Issuer:                      "https://localhost:9000",
				IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString(read(t, authserver.CACert)),
			},
			[]string{"kubelogin"},
			authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			&tls.Config{RootCAs: readCert(t, authserver.CACert)},
		},
		"InvalidCACertShouldBeSkipped": {
			kubeconfig.Values{
				Issuer:                  "http://localhost:9000",
				IDPCertificateAuthority: "cmd_test.go",
			},
			[]string{"kubelogin"},
			authserver.Config{Issuer: "http://localhost:9000"},
			&tls.Config{},
		},
		"InvalidCACertDataShouldBeSkipped": {
			kubeconfig.Values{
				Issuer:                      "http://localhost:9000",
				IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("foo")),
			},
			[]string{"kubelogin"},
			authserver.Config{Issuer: "http://localhost:9000"},
			&tls.Config{},
		},
	}

	for name, c := range data {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := c.serverConfig.Start(t)
			defer server.Shutdown(ctx)
			kcfg := kubeconfig.Create(t, &c.kubeconfigValues)
			defer os.Remove(kcfg)

			args := append(c.args, "--kubeconfig", kcfg, "--skip-open-browser")
			var eg errgroup.Group
			eg.Go(func() error {
				return di.Invoke(func(cmd adaptors.Cmd) {
					exitCode := cmd.Run(ctx, args, "HEAD")
					if exitCode != 0 {
						t.Errorf("exit status wants 0 but %d", exitCode)
					}
				})
			})
			if err := openBrowserRequest(c.clientTLS); err != nil {
				cancel()
				t.Error(err)
			}
			if err := eg.Wait(); err != nil {
				t.Fatalf("CLI returned error: %s", err)
			}
			kubeconfig.Verify(t, kcfg)
		})
	}
}

func openBrowserRequest(tlsConfig *tls.Config) error {
	time.Sleep(50 * time.Millisecond)
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	res, err := client.Get("http://localhost:8000/")
	if err != nil {
		return errors.Wrapf(err, "could not send a request")
	}
	if res.StatusCode != 200 {
		return errors.Errorf("StatusCode wants 200 but %d", res.StatusCode)
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
