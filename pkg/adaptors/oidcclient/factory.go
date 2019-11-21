// Package oidcclient provides a client of OpenID Connect.
package oidcclient

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/pipedrive/kubelogin/pkg/adaptors/certpool"
	"github.com/pipedrive/kubelogin/pkg/adaptors/logger"
	"github.com/pipedrive/kubelogin/pkg/adaptors/oidcclient/logging"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

type FactoryInterface interface {
	New(ctx context.Context, config Config) (Interface, error)
}

// Config represents a configuration of OpenID Connect client.
type Config struct {
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
func (f *Factory) New(ctx context.Context, config Config) (Interface, error) {
	var tlsConfig tls.Config
	tlsConfig.InsecureSkipVerify = config.SkipTLSVerify
	config.CertPool.SetRootCAs(&tlsConfig)
	baseTransport := &http.Transport{
		TLSClientConfig: &tlsConfig,
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
		return nil, xerrors.Errorf("could not discovery the OIDCClientFactory issuer: %w", err)
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
