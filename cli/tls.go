package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"log"

	"github.com/int128/kubelogin/kubeconfig"
	"github.com/pkg/errors"
)

func (c *CLI) tlsConfig(authProvider *kubeconfig.OIDCAuthProvider) *tls.Config {
	p := x509.NewCertPool()
	if ca := authProvider.IDPCertificateAuthority(); ca != "" {
		if err := appendCertFile(p, ca); err != nil {
			log.Printf("Skip CA certificate of idp-certificate-authority: %s", err)
		} else {
			log.Printf("Using CA certificate: %s", ca)
		}
	}
	if ca := authProvider.IDPCertificateAuthorityData(); ca != "" {
		if err := appendCertData(p, ca); err != nil {
			log.Printf("Skip CA certificate of idp-certificate-authority-data: %s", err)
		} else {
			log.Printf("Using CA certificate of idp-certificate-authority-data")
		}
	}
	cfg := &tls.Config{InsecureSkipVerify: c.SkipTLSVerify}
	if len(p.Subjects()) > 0 {
		cfg.RootCAs = p
	}
	return cfg
}

func appendCertFile(p *x509.CertPool, name string) error {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return errors.Wrapf(err, "could not read %s", name)
	}
	if p.AppendCertsFromPEM(b) != true {
		return errors.Errorf("could not append certificate from %s", name)
	}
	return nil
}

func appendCertData(p *x509.CertPool, data string) error {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return errors.Wrapf(err, "could not decode base64")
	}
	if p.AppendCertsFromPEM(b) != true {
		return errors.Errorf("could not append certificate")
	}
	return nil
}
