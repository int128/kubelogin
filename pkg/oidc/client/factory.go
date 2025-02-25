// Package client provides a client of OpenID Connect.
package client

import (
	"context"
	"fmt"
	"net/http"
	"slices"

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
	New(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error)
}

type Factory struct {
	Loader loader.Loader
	Clock  clock.Interface
	Logger logger.Interface
}

// New returns an instance of infrastructure.Interface with the given configuration.
func (f *Factory) New(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error) {
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
	provider, err := gooidc.NewProvider(ctx, prov.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery error: %w", err)
	}
	supportedPKCEMethods, err := extractSupportedPKCEMethods(provider)
	if err != nil {
		return nil, fmt.Errorf("could not determine supported PKCE methods: %w", err)
	}
	deviceAuthorizationEndpoint, err := extractDeviceAuthorizationEndpoint(provider)
	if err != nil {
		return nil, fmt.Errorf("could not determine device authorization endpoint: %w", err)
	}

	endpoint := provider.Endpoint()
	if prov.ClientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	return &client{
		httpClient: httpClient,
		provider:   provider,
		oauth2Config: oauth2.Config{
			Endpoint:     endpoint,
			ClientID:     prov.ClientID,
			ClientSecret: prov.ClientSecret,
			Scopes:       append(prov.ExtraScopes, gooidc.ScopeOpenID),
		},
		clock:                       f.Clock,
		logger:                      f.Logger,
		negotiatedPKCEMethod:        determinePKCEMethod(supportedPKCEMethods, prov.PKCEMethod),
		deviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
		useAccessToken:              prov.UseAccessToken,
	}, nil
}

func determinePKCEMethod(supportedMethods []string, preferredMethod oidc.PKCEMethod) pkce.Method {
	switch preferredMethod {
	case oidc.PKCEMethodNo:
		return pkce.NoMethod
	case oidc.PKCEMethodS256:
		return pkce.MethodS256
	default:
		if slices.Contains(supportedMethods, "S256") {
			return pkce.MethodS256
		}
		return pkce.NoMethod
	}
}

func extractSupportedPKCEMethods(provider *gooidc.Provider) ([]string, error) {
	var claims struct {
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&claims); err != nil {
		return nil, fmt.Errorf("invalid discovery document: %w", err)
	}
	return claims.CodeChallengeMethodsSupported, nil
}

func extractDeviceAuthorizationEndpoint(provider *gooidc.Provider) (string, error) {
	var claims struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return "", fmt.Errorf("invalid discovery document: %w", err)
	}
	return claims.DeviceAuthorizationEndpoint, nil
}
