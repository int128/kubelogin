package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/oidc/logging"
	"github.com/pkg/errors"
)

func newHTTPClient(config adaptors.OIDCClientConfig, logger adaptors.Logger) (*http.Client, error) {
	pool := x509.NewCertPool()
	if filename := config.Config.IDPCertificateAuthority(); filename != "" {
		logger.Debugf(1, "Loading the certificate %s", filename)
		err := appendCertificateFromFile(pool, filename)
		if err != nil {
			return nil, errors.Wrapf(err, "could not load the certificate of idp-certificate-authority")
		}
	}
	if data := config.Config.IDPCertificateAuthorityData(); data != "" {
		logger.Debugf(1, "Loading the certificate of idp-certificate-authority-data")
		err := appendEncodedCertificate(pool, data)
		if err != nil {
			return nil, errors.Wrapf(err, "could not load the certificate of idp-certificate-authority-data")
		}
	}
	if config.CACertFilename != "" {
		logger.Debugf(1, "Loading the certificate %s", config.CACertFilename)
		err := appendCertificateFromFile(pool, config.CACertFilename)
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
		Transport: &logging.Transport{
			Base: &http.Transport{
				TLSClientConfig: &tlsConfig,
				Proxy:           http.ProxyFromEnvironment,
			},
			Logger: logger,
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
