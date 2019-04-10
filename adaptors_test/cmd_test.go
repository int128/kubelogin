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
)

// Run the integration tests.
//
// 1. Start the auth server at port 9000.
// 2. Run the Cmd.
// 3. Open a request for port 8000.
// 4. Wait for the Cmd.
// 5. Shutdown the auth server.
//
func TestCmd_Run(t *testing.T) {
	k := keys.New(t)
	timeout := 500 * time.Millisecond

	t.Run("NoTLS", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := k.SignClaims(t, jwt.StandardClaims{
			Issuer:    "http://localhost:9000",
			Audience:  "kubernetes",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
		serverConfig := authserver.Config{
			Issuer:         "http://localhost:9000",
			IDToken:        idToken,
			IDTokenKeyPair: k.IDTokenKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
		}
		server := authserver.Start(t, serverConfig)
		defer server.Shutdown(ctx)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer: "http://localhost:9000",
		})
		defer os.Remove(kubeConfigFilename)

		startBrowserRequest(t, nil)
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser")
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := k.SignClaims(t, jwt.StandardClaims{
			Issuer:    "http://localhost:9000",
			Audience:  "kubernetes",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
		serverConfig := authserver.Config{
			Issuer:         "http://localhost:9000",
			IDToken:        idToken,
			IDTokenKeyPair: k.IDTokenKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
			Scope:          "profile groups openid",
		}
		server := authserver.Start(t, serverConfig)
		defer server.Shutdown(ctx)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:      "http://localhost:9000",
			ExtraScopes: "profile,groups",
		})
		defer os.Remove(kubeConfigFilename)

		startBrowserRequest(t, nil)
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser")
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("CACert", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := k.SignClaims(t, jwt.StandardClaims{
			Issuer:    "https://localhost:9000",
			Audience:  "kubernetes",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
		serverConfig := authserver.Config{
			Issuer:         "https://localhost:9000",
			IDToken:        idToken,
			IDTokenKeyPair: k.IDTokenKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
			Cert:           authserver.ServerCert,
			Key:            authserver.ServerKey,
		}
		server := authserver.Start(t, serverConfig)
		defer server.Shutdown(ctx)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  "https://localhost:9000",
			IDPCertificateAuthority: authserver.CACert,
		})
		defer os.Remove(kubeConfigFilename)

		startBrowserRequest(t, &tls.Config{RootCAs: readCert(t, authserver.CACert)})
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser")
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("CACertData", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := k.SignClaims(t, jwt.StandardClaims{
			Issuer:    "https://localhost:9000",
			Audience:  "kubernetes",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
		serverConfig := authserver.Config{
			Issuer:         "https://localhost:9000",
			IDToken:        idToken,
			IDTokenKeyPair: k.IDTokenKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
			Cert:           authserver.ServerCert,
			Key:            authserver.ServerKey,
		}
		server := authserver.Start(t, serverConfig)
		defer server.Shutdown(ctx)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                      "https://localhost:9000",
			IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString(read(t, authserver.CACert)),
		})
		defer os.Remove(kubeConfigFilename)

		startBrowserRequest(t, &tls.Config{RootCAs: readCert(t, authserver.CACert)})
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser")
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("AlreadyHaveValidToken", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		serverConfig := authserver.Config{
			Issuer:         "http://localhost:9000",
			IDTokenKeyPair: k.IDTokenKeyPair,
		}
		server := authserver.Start(t, serverConfig)
		defer server.Shutdown(ctx)

		idToken := k.SignClaims(t, jwt.StandardClaims{
			Issuer:    "http://localhost:9000",
			Audience:  "kubernetes",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
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

func startBrowserRequest(t *testing.T, tlsConfig *tls.Config) {
	t.Helper()
	go func() {
		time.Sleep(50 * time.Millisecond)
		client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
		resp, err := client.Get("http://localhost:8000/")
		if err != nil {
			t.Errorf("could not send a request: %s", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("StatusCode wants 200 but %d", resp.StatusCode)
		}
	}()
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
