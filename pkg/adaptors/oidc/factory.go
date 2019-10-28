package oidc

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
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
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	ExtraScopes   []string // optional
	CertPool      certpool.Interface
	SkipTLSVerify bool
}

type Factory struct {
	Logger logger.Interface
}

// New returns an instance of adaptors.Interface with the given configuration.
func (f *Factory) New(ctx context.Context, config ClientConfig) (Interface, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipTLSVerify,
		RootCAs:            config.CertPool.GetX509CertPool(),
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
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, xerrors.Errorf("could not discovery the OIDCFactory issuer: %w", err)
	}
	return &client{
		httpClient: httpClient,
		provider:   provider,
		oauth2Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       append(config.ExtraScopes, oidc.ScopeOpenID),
		},
		logger: f.Logger,
	}, nil
}
