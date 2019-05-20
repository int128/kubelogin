package adaptors_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/int128/kubelogin/adaptors_test/authserver"
	"github.com/int128/kubelogin/adaptors_test/keys"
	"github.com/int128/kubelogin/adaptors_test/kubeconfig"
	"github.com/int128/kubelogin/adaptors_test/logger"
	"github.com/int128/kubelogin/di"
)

// Run the integration tests.
// This assumes that port 800x and 900x are available.
//
// 1. Start the auth server at port 900x.
// 2. Run the Cmd.
// 3. Open a request for port 800x.
// 4. Wait for the Cmd.
// 5. Shutdown the auth server.
//
func TestCmd_Run(t *testing.T) {
	timeout := 1 * time.Second

	t.Run("NoTLS", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := newIDToken(t, "http://localhost:9001")
		serverConfig := authserver.Config{
			Addr:           "localhost:9001",
			Issuer:         "http://localhost:9001",
			IDToken:        idToken,
			IDTokenKeyPair: keys.JWSKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
		}
		server := authserver.Start(t, serverConfig)
		defer shutdown(t, ctx, server)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer: serverConfig.Issuer,
		})
		defer os.Remove(kubeConfigFilename)

		var wg sync.WaitGroup
		startBrowserRequest(t, ctx, &wg, "http://localhost:8001", nil)
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser", "--listen-port", "8001")
		wg.Wait()
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("env:KUBECONFIG", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := newIDToken(t, "http://localhost:9002")
		serverConfig := authserver.Config{
			Addr:           "localhost:9002",
			Issuer:         "http://localhost:9002",
			IDToken:        idToken,
			IDTokenKeyPair: keys.JWSKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
		}
		server := authserver.Start(t, serverConfig)
		defer shutdown(t, ctx, server)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer: serverConfig.Issuer,
		})
		defer os.Remove(kubeConfigFilename)

		setenv(t, "KUBECONFIG", kubeConfigFilename+string(os.PathListSeparator)+"kubeconfig/testdata/dummy.yaml")
		defer unsetenv(t, "KUBECONFIG")

		var wg sync.WaitGroup
		startBrowserRequest(t, ctx, &wg, "http://localhost:8002", nil)
		runCmd(t, ctx, "--skip-open-browser", "--listen-port", "8002")
		wg.Wait()
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("ExtraScopes", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := newIDToken(t, "http://localhost:9003")
		serverConfig := authserver.Config{
			Addr:           "localhost:9003",
			Issuer:         "http://localhost:9003",
			IDToken:        idToken,
			IDTokenKeyPair: keys.JWSKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
			Scope:          "profile groups openid",
		}
		server := authserver.Start(t, serverConfig)
		defer shutdown(t, ctx, server)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:      serverConfig.Issuer,
			ExtraScopes: "profile,groups",
		})
		defer os.Remove(kubeConfigFilename)

		var wg sync.WaitGroup
		startBrowserRequest(t, ctx, &wg, "http://localhost:8003", nil)
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser", "--listen-port", "8003")
		wg.Wait()
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("CACert", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := newIDToken(t, "https://localhost:9004")
		serverConfig := authserver.Config{
			Addr:           "localhost:9004",
			Issuer:         "https://localhost:9004",
			IDToken:        idToken,
			IDTokenKeyPair: keys.JWSKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
			TLSServerCert:  keys.TLSServerCert,
			TLSServerKey:   keys.TLSServerKey,
		}
		server := authserver.Start(t, serverConfig)
		defer shutdown(t, ctx, server)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                  serverConfig.Issuer,
			IDPCertificateAuthority: keys.TLSCACert,
		})
		defer os.Remove(kubeConfigFilename)

		var wg sync.WaitGroup
		startBrowserRequest(t, ctx, &wg, "http://localhost:8004", keys.TLSCACertAsConfig)
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser", "--listen-port", "8004")
		wg.Wait()
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("CACertData", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		idToken := newIDToken(t, "https://localhost:9005")
		serverConfig := authserver.Config{
			Addr:           "localhost:9005",
			Issuer:         "https://localhost:9005",
			IDToken:        idToken,
			IDTokenKeyPair: keys.JWSKeyPair,
			RefreshToken:   "REFRESH_TOKEN",
			TLSServerCert:  keys.TLSServerCert,
			TLSServerKey:   keys.TLSServerKey,
		}
		server := authserver.Start(t, serverConfig)
		defer shutdown(t, ctx, server)

		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:                      serverConfig.Issuer,
			IDPCertificateAuthorityData: keys.TLSCACertAsBase64,
		})
		defer os.Remove(kubeConfigFilename)

		var wg sync.WaitGroup
		startBrowserRequest(t, ctx, &wg, "http://localhost:8005", keys.TLSCACertAsConfig)
		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser", "--listen-port", "8005")
		wg.Wait()
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken:      idToken,
			RefreshToken: "REFRESH_TOKEN",
		})
	})

	t.Run("AlreadyHaveValidToken", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		serverConfig := authserver.Config{
			Addr:           "localhost:9006",
			Issuer:         "http://localhost:9006",
			IDTokenKeyPair: keys.JWSKeyPair,
		}
		server := authserver.Start(t, serverConfig)
		defer shutdown(t, ctx, server)

		idToken := newIDToken(t, serverConfig.Issuer)
		kubeConfigFilename := kubeconfig.Create(t, &kubeconfig.Values{
			Issuer:  serverConfig.Issuer,
			IDToken: idToken,
		})
		defer os.Remove(kubeConfigFilename)

		runCmd(t, ctx, "--kubeconfig", kubeConfigFilename, "--skip-open-browser")
		kubeconfig.Verify(t, kubeConfigFilename, kubeconfig.AuthProviderConfig{
			IDToken: idToken,
		})
	})
}

func newIDToken(t *testing.T, issuer string) string {
	t.Helper()
	var claims struct {
		jwt.StandardClaims
		Groups []string `json:"groups"`
	}
	claims.StandardClaims = jwt.StandardClaims{
		Issuer:    issuer,
		Audience:  "kubernetes",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Subject:   "SUBJECT",
		IssuedAt:  time.Now().Unix(),
	}
	claims.Groups = []string{"admin", "users"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(keys.JWSKeyPair)
	if err != nil {
		t.Fatalf("Could not sign the claims: %s", err)
	}
	return s
}

func runCmd(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	cmd := di.NewCmd(logger.New(t))
	exitCode := cmd.Run(ctx, append([]string{"kubelogin", "--v=1"}, args...), "HEAD")
	if exitCode != 0 {
		t.Errorf("exit status wants 0 but %d", exitCode)
	}
}

func startBrowserRequest(t *testing.T, ctx context.Context, wg *sync.WaitGroup, url string, tlsConfig *tls.Config) {
	t.Helper()
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Errorf("could not create a request: %s", err)
		return
	}
	req = req.WithContext(ctx)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("could not send a request: %s", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("StatusCode wants 200 but %d", resp.StatusCode)
		}
	}()
	wg.Add(1)
}

func shutdown(t *testing.T, ctx context.Context, s *http.Server) {
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Could not shutdown the auth server: %s", err)
	}
}

func setenv(t *testing.T, key, value string) {
	t.Helper()
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("Could not set the env var %s=%s: %s", key, value, err)
	}
}

func unsetenv(t *testing.T, key string) {
	t.Helper()
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Could not unset the env var %s: %s", key, err)
	}
}
