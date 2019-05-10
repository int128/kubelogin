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

func (h *HTTP) NewClient(config adaptors.HTTPClientConfig) (*http.Client, error) {
	pool := x509.NewCertPool()
	if config.OIDCConfig.IDPCertificateAuthority() != "" {
		err := appendCertificateFromFile(pool, config.OIDCConfig.IDPCertificateAuthority())
		if err != nil {
			return nil, errors.Wrapf(err, "could not load the certificate of idp-certificate-authority")
		}
	}
	if config.OIDCConfig.IDPCertificateAuthorityData() != "" {
		err := appendEncodedCertificate(pool, config.OIDCConfig.IDPCertificateAuthorityData())
		if err != nil {
			return nil, errors.Wrapf(err, "could not load the certificate of idp-certificate-authority-data")
		}
	}
	if config.CertificateAuthorityFilename != "" {
		err := appendCertificateFromFile(pool, config.CertificateAuthorityFilename)
		if err != nil {
			return nil, errors.Wrapf(err, "could not load the certificate")
		}
	}

	var tlsConfig tls.Config
	if len(pool.Subjects()) > 0 {
		tlsConfig.RootCAs = pool
	}
	tlsConfig.InsecureSkipVerify = config.SkipTLSVerify
	return &http.Client{
		Transport: &infrastructure.LoggingTransport{
			Base: &http.Transport{
				TLSClientConfig: &tlsConfig,
				Proxy:           http.ProxyFromEnvironment,
			},
			Logger: h.Logger,
		},
	}, nil
}

func appendCertificateFromFile(pool *x509.CertPool, filename string) error {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.Wrapf(err, "could not read %s", filename)
	}
	if !pool.AppendCertsFromPEM(b) {
		return errors.Errorf("could not append certificate from %s", filename)
	}
	return nil
}

func appendEncodedCertificate(pool *x509.CertPool, base64String string) error {
	b, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return errors.Wrapf(err, "could not decode base64")
	}
	if !pool.AppendCertsFromPEM(b) {
		return errors.Errorf("could not append certificate")
	}
	return nil
}
