package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/oidc/logging"
	"golang.org/x/xerrors"
)

func newHTTPClient(config adaptors.OIDCClientConfig, logger adaptors.Logger) (*http.Client, error) {
	pool := x509.NewCertPool()
	if config.Config.IDPCertificateAuthority != "" {
		logger.Debugf(1, "Loading the certificate %s", config.Config.IDPCertificateAuthority)
		err := appendCertificateFromFile(pool, config.Config.IDPCertificateAuthority)
		if err != nil {
			return nil, xerrors.Errorf("could not load the certificate of idp-certificate-authority: %w", err)
		}
	}
	if config.Config.IDPCertificateAuthorityData != "" {
		logger.Debugf(1, "Loading the certificate of idp-certificate-authority-data")
		err := appendEncodedCertificate(pool, config.Config.IDPCertificateAuthorityData)
		if err != nil {
			return nil, xerrors.Errorf("could not load the certificate of idp-certificate-authority-data: %w", err)
		}
	}
	if config.CACertFilename != "" {
		logger.Debugf(1, "Loading the certificate %s", config.CACertFilename)
		err := appendCertificateFromFile(pool, config.CACertFilename)
		if err != nil {
			return nil, xerrors.Errorf("could not load the certificate: %w", err)
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
		return xerrors.Errorf("could not read %s: %w", filename, err)
	}
	if !pool.AppendCertsFromPEM(b) {
		return xerrors.Errorf("could not append certificate from %s", filename)
	}
	return nil
}

func appendEncodedCertificate(pool *x509.CertPool, base64String string) error {
	b, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return xerrors.Errorf("could not decode base64: %w", err)
	}
	if !pool.AppendCertsFromPEM(b) {
		return xerrors.Errorf("could not append certificate")
	}
	return nil
}
