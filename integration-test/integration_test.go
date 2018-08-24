package integration

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
)

const caCert = "testdata/authserver-ca.crt"
const tlsCert = "testdata/authserver.crt"
const tlsKey = "testdata/authserver.key"

func Test(t *testing.T) {
	ctx := context.Background()
	authServer := &http.Server{
		Addr:    "localhost:9000",
		Handler: NewAuthHandler(t, "http://localhost:9000"),
	}
	defer authServer.Shutdown(ctx)
	kubeconfig := createKubeconfig(t, &kubeconfigValues{
		Issuer: "http://localhost:9000",
	})
	defer os.Remove(kubeconfig)

	go listenAndServe(t, authServer)
	go authenticate(t, &tls.Config{})

	c := cli.CLI{
		KubeConfig: kubeconfig,
	}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	verifyKubeconfig(t, kubeconfig)
}

func TestWithSkipTLSVerify(t *testing.T) {
	ctx := context.Background()
	authServer := &http.Server{
		Addr:    "localhost:9000",
		Handler: NewAuthHandler(t, "https://localhost:9000"),
	}
	defer authServer.Shutdown(ctx)
	kubeconfig := createKubeconfig(t, &kubeconfigValues{
		Issuer: "https://localhost:9000",
	})
	defer os.Remove(kubeconfig)

	go listenAndServeTLS(t, authServer)
	go authenticate(t, &tls.Config{InsecureSkipVerify: true})

	c := cli.CLI{
		KubeConfig:    kubeconfig,
		SkipTLSVerify: true,
	}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	verifyKubeconfig(t, kubeconfig)
}

func TestWithCACert(t *testing.T) {
	ctx := context.Background()
	authServer := &http.Server{
		Addr:    "localhost:9000",
		Handler: NewAuthHandler(t, "https://localhost:9000"),
	}
	defer authServer.Shutdown(ctx)
	kubeconfig := createKubeconfig(t, &kubeconfigValues{
		Issuer:                  "https://localhost:9000",
		IDPCertificateAuthority: caCert,
	})
	defer os.Remove(kubeconfig)

	go listenAndServeTLS(t, authServer)
	go authenticate(t, &tls.Config{RootCAs: loadCACert(t)})

	c := cli.CLI{
		KubeConfig: kubeconfig,
	}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	verifyKubeconfig(t, kubeconfig)
}

func TestWithCACertData(t *testing.T) {
	ctx := context.Background()
	authServer := &http.Server{
		Addr:    "localhost:9000",
		Handler: NewAuthHandler(t, "https://localhost:9000"),
	}
	defer authServer.Shutdown(ctx)
	b, err := ioutil.ReadFile(caCert)
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig := createKubeconfig(t, &kubeconfigValues{
		Issuer: "https://localhost:9000",
		IDPCertificateAuthorityData: base64.StdEncoding.EncodeToString(b),
	})
	defer os.Remove(kubeconfig)

	go listenAndServeTLS(t, authServer)
	go authenticate(t, &tls.Config{RootCAs: loadCACert(t)})

	c := cli.CLI{
		KubeConfig: kubeconfig,
	}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	verifyKubeconfig(t, kubeconfig)
}

func authenticate(t *testing.T, tlsConfig *tls.Config) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	res, err := client.Get("http://localhost:8000/")
	if err != nil {
		t.Error(err)
		return
	}
	if res.StatusCode != 200 {
		t.Errorf("StatusCode wants 200 but %d: res=%+v", res.StatusCode, res)
	}
}

func loadCACert(t *testing.T) *x509.CertPool {
	p := x509.NewCertPool()
	b, err := ioutil.ReadFile(caCert)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AppendCertsFromPEM(b) {
		t.Fatalf("Could not AppendCertsFromPEM")
	}
	return p
}

func listenAndServe(t *testing.T, s *http.Server) {
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

func listenAndServeTLS(t *testing.T, s *http.Server) {
	if err := s.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}
