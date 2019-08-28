package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidc/logging"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

type FactoryInterface interface {
	New(ctx context.Context, config ClientConfig) (Interface, error)
}

// ClientConfig represents a configuration of an Interface to create.
type ClientConfig struct {
	Config         kubeconfig.OIDCConfig
	CACertFilename string
	SkipTLSVerify  bool
}

type Factory struct {
	Logger logger.Interface
}

// New returns an instance of adaptors.Interface with the given configuration.
func (f *Factory) New(ctx context.Context, config ClientConfig) (Interface, error) {
	tlsConfig, err := f.tlsConfigFor(config)
	if err != nil {
		return nil, xerrors.Errorf("could not initialize TLS config: %w", err)
	}
	baseTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	loggingTransport := &logging.Transport{
		Base:   baseTransport,
		Logger: f.Logger,
	}
	httpClient := &http.Client{
		Transport: loggingTransport,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	provider, err := oidc.NewProvider(ctx, config.Config.IDPIssuerURL)
	if err != nil {
		return nil, xerrors.Errorf("could not discovery the OIDCFactory issuer: %w", err)
	}
	return &client{
		httpClient: httpClient,
		provider:   provider,
		oauth2Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     config.Config.ClientID,
			ClientSecret: config.Config.ClientSecret,
			Scopes:       append(config.Config.ExtraScopes, oidc.ScopeOpenID),
		},
		logger: f.Logger,
	}, nil
}

func (f *Factory) tlsConfigFor(config ClientConfig) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if config.Config.IDPCertificateAuthority != "" {
		f.Logger.V(1).Infof("loading the certificate %s", config.Config.IDPCertificateAuthority)
		err := appendCertificateFromFile(pool, config.Config.IDPCertificateAuthority)
		if err != nil {
			return nil, xerrors.Errorf("could not load the certificate of idp-certificate-authority: %w", err)
		}
	}
	if config.Config.IDPCertificateAuthorityData != "" {
		f.Logger.V(1).Infof("loading the certificate of idp-certificate-authority-data")
		err := appendEncodedCertificate(pool, config.Config.IDPCertificateAuthorityData)
		if err != nil {
			return nil, xerrors.Errorf("could not load the certificate of idp-certificate-authority-data: %w", err)
		}
	}
	if config.CACertFilename != "" {
		f.Logger.V(1).Infof("loading the certificate %s", config.CACertFilename)
		err := appendCertificateFromFile(pool, config.CACertFilename)
		if err != nil {
			return nil, xerrors.Errorf("could not load the certificate: %w", err)
		}
	}
	c := &tls.Config{
		InsecureSkipVerify: config.SkipTLSVerify,
	}
	if len(pool.Subjects()) > 0 {
		c.RootCAs = pool
	}
	return c, nil
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
