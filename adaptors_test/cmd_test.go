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

	"github.com/dgrijalva/jwt-go"
	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/adaptors_test/authserver"
	"github.com/int128/kubelogin/adaptors_test/keys"
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
	k := keys.New(t)

	data := map[string]struct {
		kubeconfigValues kubeconfig.Values
		args             []string
		serverConfig     authserver.Config
		clientTLS        *tls.Config
	}{
		"NoTLS": {
			kubeconfig.Values{Issuer: "http://localhost:9000"},
			[]string{"kubelogin"},
			authserver.Config{
				Issuer:         "http://localhost:9000",
				IDToken:        issueIDToken(t, k, "http://localhost:9000"),
				IDTokenKeyPair: k.IDTokenKeyPair,
			},
			&tls.Config{},
		},
		"ExtraScope": {
			kubeconfig.Values{
				Issuer:      "http://localhost:9000",
				ExtraScopes: "profile groups",
			},
			[]string{"kubelogin"},
			authserver.Config{
				Issuer:         "http://localhost:9000",
				Scope:          "profile groups openid",
				IDToken:        issueIDToken(t, k, "http://localhost:9000"),
				IDTokenKeyPair: k.IDTokenKeyPair,
			},
			&tls.Config{},
		},
		"SkipTLSVerify": {
			kubeconfig.Values{Issuer: "https://localhost:9000"},
			[]string{"kubelogin", "--insecure-skip-tls-verify"},
			authserver.Config{
				Issuer:         "https://localhost:9000",
				Cert:           authserver.ServerCert,
				Key:            authserver.ServerKey,
				IDToken:        issueIDToken(t, k, "https://localhost:9000"),
				IDTokenKeyPair: k.IDTokenKeyPair,
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
				Issuer:         "https://localhost:9000",
				Cert:           authserver.ServerCert,
				Key:            authserver.ServerKey,
				IDToken:        issueIDToken(t, k, "https://localhost:9000"),
				IDTokenKeyPair: k.IDTokenKeyPair,
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
				Issuer:         "https://localhost:9000",
				Cert:           authserver.ServerCert,
				Key:            authserver.ServerKey,
				IDToken:        issueIDToken(t, k, "https://localhost:9000"),
				IDTokenKeyPair: k.IDTokenKeyPair,
			},
			&tls.Config{RootCAs: readCert(t, authserver.CACert)},
		},
		"InvalidCACertShouldBeSkipped": {
			kubeconfig.Values{
				Issuer:                  "http://localhost:9000",
				IDPCertificateAuthority: "cmd_test.go",
			},
			[]string{"kubelogin"},
			authserver.Config{
				Issuer:         "http://localhost:9000",
				IDToken:        issueIDToken(t, k, "http://localhost:9000"),
				IDTokenKeyPair: k.IDTokenKeyPair,
			},
			&tls.Config{},
		},
		"InvalidCACertDataShouldBeSkipped": {
			kubeconfig.Values{
				Issuer:                      "http://localhost:9000",
				IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("foo")),
			},
			[]string{"kubelogin"},
			authserver.Config{
				Issuer:         "http://localhost:9000",
				IDToken:        issueIDToken(t, k, "http://localhost:9000"),
				IDTokenKeyPair: k.IDTokenKeyPair,
			},
			&tls.Config{},
		},
	}

	for name, c := range data {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := authserver.Start(t, c.serverConfig)
			defer server.Shutdown(ctx)
			kcfg := kubeconfig.Create(t, &c.kubeconfigValues)
			defer os.Remove(kcfg)

			//TODO: replace with runCmd()
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
			kubeconfig.Verify(t, kcfg, kubeconfig.AuthProviderConfig{
				IDToken:      c.serverConfig.IDToken,
				RefreshToken: "44df4c82-5ce7-4260-b54d-1da0d396ef2a",
			})
		})
	}

	t.Run("AlreadyHaveValidToken", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		serverConfig := authserver.Config{
			Issuer:         "http://localhost:9000",
			IDTokenKeyPair: k.IDTokenKeyPair,
		}
		server := authserver.Start(t, serverConfig)
		defer server.Shutdown(ctx)

		idToken := issueIDToken(t, k, "http://localhost:9000")
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:  "http://localhost:9000",
			IDToken: idToken,
		})
		defer os.Remove(kubeConfigFilename)

		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser")

		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken: idToken,
		})
	})
}

func issueIDToken(t *testing.T, k keys.Keys, issuer string) string {
	t.Helper()
	return k.SignClaims(t, jwt.StandardClaims{
		Issuer:    issuer,
		Audience:  "kubernetes",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
}

func runCmd(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	if err := di.Invoke(func(cmd adaptors.Cmd) {
		exitCode := cmd.Run(ctx, append([]string{"kubelogin"}, args...), "HEAD")
		if exitCode != 0 {
			t.Errorf("exit status wants 0 but %d", exitCode)
		}
	}); err != nil {
		t.Errorf("Invoke returned error: %+v", err)
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
