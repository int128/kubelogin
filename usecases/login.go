package usecases

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/int128/kubelogin/auth"
	"github.com/int128/kubelogin/kubeconfig"
	"github.com/int128/kubelogin/usecases/interfaces"
)

type Login struct{}

func (u *Login) Do(ctx context.Context, in usecases.LoginIn) error {
	cfg := in.Config
	//TODO: replace with klog
	log.Printf("Using current-context: %s", cfg.CurrentContext)
	authProvider, err := kubeconfig.FindOIDCAuthProvider(&cfg)
	if err != nil {
		//TODO: replace with errors.wrap()
		return fmt.Errorf(`Could not find OIDC configuration in kubeconfig: %s
			Did you setup kubectl for OIDC authentication?
				kubectl config set-credentials %s \
					--auth-provider oidc \
					--auth-provider-arg idp-issuer-url=https://issuer.example.com \
					--auth-provider-arg client-id=YOUR_CLIENT_ID \
					--auth-provider-arg client-secret=YOUR_CLIENT_SECRET`,
			err, cfg.CurrentContext)
	}
	tlsConfig := tlsConfig(authProvider, in.SkipTLSVerify)
	authConfig := &auth.Config{
		Issuer:          authProvider.IDPIssuerURL(),
		ClientID:        authProvider.ClientID(),
		ClientSecret:    authProvider.ClientSecret(),
		ExtraScopes:     authProvider.ExtraScopes(),
		Client:          &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		LocalServerPort: in.ListenPort,
		SkipOpenBrowser: in.SkipOpenBrowser,
	}
	token, err := authConfig.GetTokenSet(ctx)
	if err != nil {
		return fmt.Errorf("error while getting a token from the OIDC provider: %s", err)
	}

	authProvider.SetIDToken(token.IDToken)
	authProvider.SetRefreshToken(token.RefreshToken)
	if err := kubeconfig.Write(&cfg, in.ConfigPath); err != nil {
		return fmt.Errorf("error while writing config: %s", err)
	}
	log.Printf("Updated %s", in.ConfigPath)
	return nil
}

func tlsConfig(authProvider *kubeconfig.OIDCAuthProvider, skipTLSVerify bool) *tls.Config {
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
	cfg := &tls.Config{InsecureSkipVerify: skipTLSVerify}
	if len(p.Subjects()) > 0 {
		cfg.RootCAs = p
	}
	return cfg
}

func appendCertFile(p *x509.CertPool, name string) error {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return fmt.Errorf("error while reading %s: %s", name, err)
	}
	if p.AppendCertsFromPEM(b) != true {
		return fmt.Errorf("error while appending the certificate from %s", name)
	}
	return nil
}

func appendCertData(p *x509.CertPool, data string) error {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("error while decoding base64: %s", err)
	}
	if p.AppendCertsFromPEM(b) != true {
		return fmt.Errorf("error while appending certificate")
	}
	return nil
}
