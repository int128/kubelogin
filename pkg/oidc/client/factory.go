// Package client provides a client of OpenID Connect.
package client

import (
	"context"
	"fmt"
	"net/http"

	gooidc "github.com/coreos/go-oidc"
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/clock"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client/logging"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tlsclientconfig/loader"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_client/mock_factory.go github.com/int128/kubelogin/pkg/oidc/client FactoryInterface

var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
)

type FactoryInterface interface {
	New(ctx context.Context, p oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error)
}

type Factory struct {
	Loader loader.Loader
	Clock  clock.Interface
	Logger logger.Interface
}

// New returns an instance of adaptors.Interface with the given configuration.
func (f *Factory) New(ctx context.Context, p oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error) {
	rawTLSClientConfig, err := f.Loader.Load(tlsClientConfig)
	if err != nil {
		return nil, xerrors.Errorf("could not load the TLS client config: %w", err)
	}
	baseTransport := &http.Transport{
		TLSClientConfig: rawTLSClientConfig,
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
	provider, err := gooidc.NewProvider(ctx, p.IssuerURL)
	if err != nil {
		return nil, xerrors.Errorf("oidc discovery error: %w", err)
	}
	supportedPKCEMethods, err := extractSupportedPKCEMethods(provider)
	if err != nil {
		return nil, xerrors.Errorf("could not determine supported PKCE methods: %w", err)
	}
	return &client{
		httpClient: httpClient,
		provider:   provider,
		oauth2Config: oauth2.Config{
			Endpoint:     provider.Endpoint(),
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			Scopes:       append(p.ExtraScopes, gooidc.ScopeOpenID),
		},
		clock:                f.Clock,
		logger:               f.Logger,
		supportedPKCEMethods: supportedPKCEMethods,
	}, nil
}

func extractSupportedPKCEMethods(provider *gooidc.Provider) ([]string, error) {
	var d struct {
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&d); err != nil {
		return nil, fmt.Errorf("invalid discovery document: %w", err)
	}
	return d.CodeChallengeMethodsSupported, nil
}
