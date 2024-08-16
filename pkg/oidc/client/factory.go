// Package client provides a client of OpenID Connect.
package client

import (
	"context"
	"fmt"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/oidc/client/logging"
	"github.com/int128/kubelogin/pkg/pkce"
	"github.com/int128/kubelogin/pkg/tlsclientconfig"
	"github.com/int128/kubelogin/pkg/tlsclientconfig/loader"
	"golang.org/x/oauth2"
)

var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
)

type FactoryInterface interface {
	New(ctx context.Context, p oidc.Provider, tlsClientConfig tlsclientconfig.Config, useAccessToken bool) (Interface, error)
}

type Factory struct {
	Loader loader.Loader
	Clock  clock.Interface
	Logger logger.Interface
}

// New returns an instance of infrastructure.Interface with the given configuration.
func (f *Factory) New(ctx context.Context, p oidc.Provider, tlsClientConfig tlsclientconfig.Config, useAccessToken bool) (Interface, error) {
	rawTLSClientConfig, err := f.Loader.Load(tlsClientConfig)
	if err != nil {
		return nil, fmt.Errorf("could not load the TLS client config: %w", err)
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
		return nil, fmt.Errorf("oidc discovery error: %w", err)
	}
	supportedPKCEMethods, err := extractSupportedPKCEMethods(provider)
	if err != nil {
		return nil, fmt.Errorf("could not determine supported PKCE methods: %w", err)
	}
	if len(supportedPKCEMethods) == 0 && p.UsePKCE {
		supportedPKCEMethods = []string{pkce.MethodS256}
	}
	deviceAuthorizationEndpoint, err := extractDeviceAuthorizationEndpoint(provider)
	if err != nil {
		return nil, fmt.Errorf("could not determine device authorization endpoint: %w", err)
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
		clock:                       f.Clock,
		logger:                      f.Logger,
		supportedPKCEMethods:        supportedPKCEMethods,
		deviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
		useAccessToken:              useAccessToken,
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

func extractDeviceAuthorizationEndpoint(provider *gooidc.Provider) (string, error) {
	var d struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&d); err != nil {
		return "", fmt.Errorf("invalid discovery document: %w", err)
	}
	return d.DeviceAuthorizationEndpoint, nil
}
