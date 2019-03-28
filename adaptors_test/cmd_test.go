package adaptors_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors_test/authserver"
	"github.com/int128/kubelogin/adaptors_test/kubeconfig"
	"github.com/int128/kubelogin/usecases"
)

// Run end-to-end tests with a stub server.
//
// 1. Start the auth server at port 9000.
// 2. Run the CLI.
// 3. Open a request for port 8000.
// 4. Wait for the CLI.
// 5. Shutdown the auth server.
//
func TestCmd_Run(t *testing.T) {
	testCases := map[string]struct {
		kubeconfigValues kubeconfig.Values
		serverConfig     authserver.Config
		clientConfig     *tls.Config
		extraArgs        []string
	}{
		"NoTLS": {
			kubeconfigValues: kubeconfig.Values{Issuer: "http://localhost:9000"},
			serverConfig:     authserver.Config{Issuer: "http://localhost:9000"},
		},
		"ExtraScope": {
			kubeconfigValues: kubeconfig.Values{
				Issuer:      "http://localhost:9000",
				ExtraScopes: "profile groups",
			},
			serverConfig: authserver.Config{
				Issuer: "http://localhost:9000",
				Scope:  "profile groups openid",
			},
		},
		"SkipTLSVerify": {
			kubeconfigValues: kubeconfig.Values{Issuer: "https://localhost:9000"},
			serverConfig: authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			clientConfig: &tls.Config{InsecureSkipVerify: true},
			extraArgs:    []string{"--insecure-skip-tls-verify"},
		},
		"CACert": {
			kubeconfigValues: kubeconfig.Values{
				Issuer:                  "https://localhost:9000",
				IDPCertificateAuthority: authserver.CACert,
			},
			serverConfig: authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			clientConfig: &tls.Config{RootCAs: readCert(t, authserver.CACert)},
		},
		"CACertData": {
			kubeconfigValues: kubeconfig.Values{
				Issuer:                      "https://localhost:9000",
				IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString(read(t, authserver.CACert)),
			},
			serverConfig: authserver.Config{
				Issuer: "https://localhost:9000",
				Cert:   authserver.ServerCert,
				Key:    authserver.ServerKey,
			},
			clientConfig: &tls.Config{RootCAs: readCert(t, authserver.CACert)},
		},
		"InvalidCACertShouldBeSkipped": {
			kubeconfigValues: kubeconfig.Values{
				Issuer:                  "http://localhost:9000",
				IDPCertificateAuthority: "cmd_test.go",
			},
			serverConfig: authserver.Config{Issuer: "http://localhost:9000"},
		},
		"InvalidCACertDataShouldBeSkipped": {
			kubeconfigValues: kubeconfig.Values{
				Issuer:                      "http://localhost:9000",
				IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("INVALID")),
			},
			serverConfig: authserver.Config{Issuer: "http://localhost:9000"},
		},
	}

	for name, c := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := c.serverConfig.Start(t)
			defer server.Shutdown(ctx)
			kcfg := kubeconfig.Create(t, &c.kubeconfigValues)
			defer os.Remove(kcfg)

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				cmd := adaptors.Cmd{
					Login: &usecases.Login{},
				}
				args := append([]string{
					"kubelogin",
					"--kubeconfig", kcfg,
					"--skip-open-browser",
				}, c.extraArgs...)
				if exitCode := cmd.Run(ctx, args); exitCode != 0 {
					t.Errorf("exitCode wants 0 but %d", exitCode)
				}
			}()
			go func() {
				defer wg.Done()
				if err := openBrowserRequest(c.clientConfig); err != nil {
					cancel()
					t.Error(err)
				}
			}()
			wg.Wait()
			kubeconfig.Verify(t, kcfg)
		})
	}
}

func openBrowserRequest(tlsConfig *tls.Config) error {
	time.Sleep(50 * time.Millisecond)
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	res, err := client.Get("http://localhost:8000/")
	if err != nil {
		return fmt.Errorf("error while sending a request: %s", err)
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
