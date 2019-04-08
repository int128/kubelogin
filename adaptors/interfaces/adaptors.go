package adaptors

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/coreos/go-oidc"
	"k8s.io/client-go/tools/clientcmd/api"
)

//go:generate mockgen -package mock_adaptors -destination ../mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/adaptors/interfaces KubeConfig,HTTP,HTTPClientConfig,OIDC

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type KubeConfig interface {
	LoadFromFile(filename string) (*api.Config, error)
	WriteToFile(config *api.Config, filename string) error
}

type HTTP interface {
	NewClientConfig() HTTPClientConfig
	NewClient(config HTTPClientConfig) (*http.Client, error)
}

type HTTPClientConfig interface {
	AddCertificateFromFile(filename string) error
	AddEncodedCertificate(base64String string) error
	SetSkipTLSVerify(b bool)

	TLSConfig() *tls.Config
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
	VerifiedIDToken *oidc.IDToken
	IDToken         string
	RefreshToken    string
}

type Logger interface {
	Logf(format string, v ...interface{})
}
