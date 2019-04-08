package adaptors

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/pkg/errors"
)

type HTTP struct{}

func (*HTTP) NewClientConfig() adaptors.HTTPClientConfig {
	return &httpClientConfig{
		certPool: x509.NewCertPool(),
	}
}

func (*HTTP) NewClient(config adaptors.HTTPClientConfig) (*http.Client, error) {
	transport := &http.Transport{}
	//TODO: replace with http.ProxyFromEnvironmentURL or go-ieproxy
	// https://github.com/int128/kubelogin/issues/31
	val, ok := os.LookupEnv("HTTPS_PROXY")
	if ok {
		proxyURL, err := url.Parse(val)
		if err != nil {
			log.Printf("HTTPS_PROXY %s cannot be parsed into a URL\n", val)
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	//
	transport.TLSClientConfig = config.TLSConfig()
	return &http.Client{Transport: transport}, nil
}

type httpClientConfig struct {
	certPool      *x509.CertPool
	skipTLSVerify bool
}

func (c *httpClientConfig) AddCertificateFromFile(filename string) error {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.Wrapf(err, "could not read %s", filename)
	}
	if c.certPool.AppendCertsFromPEM(b) != true {
		return errors.Errorf("could not append certificate from %s", filename)
	}
	return nil
}

func (c *httpClientConfig) AddEncodedCertificate(base64String string) error {
	b, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return errors.Wrapf(err, "could not decode base64")
	}
	if c.certPool.AppendCertsFromPEM(b) != true {
		return errors.Errorf("could not append certificate")
	}
	return nil
}

func (c *httpClientConfig) TLSConfig() *tls.Config {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.skipTLSVerify,
	}
	if len(c.certPool.Subjects()) > 0 {
		tlsConfig.RootCAs = c.certPool
	}
	return tlsConfig
}

func (c *httpClientConfig) SetSkipTLSVerify(b bool) {
	c.skipTLSVerify = b
}
