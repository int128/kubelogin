package adaptors

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/infrastructure"
	"github.com/pkg/errors"
	"go.uber.org/dig"
)

func NewHTTP(i HTTP) adaptors.HTTP {
	return &i
}

type HTTP struct {
	dig.In
	Logger adaptors.Logger
}

func (*HTTP) NewClientConfig() adaptors.HTTPClientConfig {
	return &httpClientConfig{
		certPool: x509.NewCertPool(),
	}
}

func (h *HTTP) NewClient(config adaptors.HTTPClientConfig) (*http.Client, error) {
	return &http.Client{
		Transport: &infrastructure.LoggingTransport{
			Base: &http.Transport{
				TLSClientConfig: config.TLSConfig(),
				Proxy:           http.ProxyFromEnvironment,
			},
			Logger: h.Logger,
		},
	}, nil
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
