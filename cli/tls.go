package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/int128/kubelogin/kubeconfig"
)

func (c *CLI) tlsConfig(authProvider *kubeconfig.OIDCAuthProvider) (*tls.Config, error) {
	p := x509.NewCertPool()
	if ca := authProvider.IDPCertificateAuthority(); ca != "" {
		b, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("Could not read %s: %s", ca, err)
		}
		if p.AppendCertsFromPEM(b) != true {
			return nil, fmt.Errorf("Could not append CA certificate from %s", ca)
		}
		log.Printf("Using CA certificate: %s", ca)
	}
	if ca := authProvider.IDPCertificateAuthorityData(); ca != "" {
		b, err := base64.StdEncoding.DecodeString(ca)
		if err != nil {
			return nil, fmt.Errorf("Could not decode idp-certificate-authority-data: %s", err)
		}
		if p.AppendCertsFromPEM(b) != true {
			return nil, fmt.Errorf("Could not append CA certificate from idp-certificate-authority-data")
		}
		log.Printf("Using CA certificate: idp-certificate-authority-data")
	}

	cfg := &tls.Config{InsecureSkipVerify: c.SkipTLSVerify}
	if len(p.Subjects()) > 0 {
		cfg.RootCAs = p
	}
	return cfg, nil
}
