package adaptors

import (
	"context"
	"crypto/tls"
	"net/http"

	"k8s.io/client-go/tools/clientcmd/api"
)

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type KubeConfig interface {
	LoadFromFile(filename string) (*api.Config, error)
	WriteToFile(config *api.Config, filename string) error
}

type HTTP interface {
	NewClient(in HTTPClientIn) (*http.Client, error)
}

type HTTPClientIn struct {
	TLSClientConfig *tls.Config
}

type OIDC interface {
	Authenticate(ctx context.Context, in OIDCAuthenticateIn) (*OIDCAuthenticateOut, error)
}

type OIDCAuthenticateIn struct {
	Issuer          string
	ClientID        string
	ClientSecret    string
	ExtraScopes     []string     // Additional scopes
	Client          *http.Client // HTTP client for oidc and oauth2
	LocalServerPort int          // HTTP server port
	SkipOpenBrowser bool         // skip opening browser if true
}

type OIDCAuthenticateOut struct {
	IDToken      string
	RefreshToken string
}
