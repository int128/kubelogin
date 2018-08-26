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
	if authProvider.IDPCertificateAuthority() != "" {
		b, err := ioutil.ReadFile(authProvider.IDPCertificateAuthority())
		if err != nil {
			return nil, fmt.Errorf("Could not read idp-certificate-authority: %s", err)
		}
		if p.AppendCertsFromPEM(b) != true {
			return nil, fmt.Errorf("Could not load CA certificate from idp-certificate-authority: %s", err)
		}
		log.Printf("Using CA certificate: %s", authProvider.IDPCertificateAuthority())
	}
	if authProvider.IDPCertificateAuthorityData() != "" {
		b, err := base64.StdEncoding.DecodeString(authProvider.IDPCertificateAuthorityData())
		if err != nil {
			return nil, fmt.Errorf("Could not decode idp-certificate-authority-data: %s", err)
		}
		if p.AppendCertsFromPEM(b) != true {
			return nil, fmt.Errorf("Could not load CA certificate from idp-certificate-authority-data: %s", err)
		}
		log.Printf("Using CA certificate of idp-certificate-authority-data")
	}

	cfg := &tls.Config{InsecureSkipVerify: c.SkipTLSVerify}
	if len(p.Subjects()) > 0 {
		cfg.RootCAs = p
	}
	return cfg, nil
}
