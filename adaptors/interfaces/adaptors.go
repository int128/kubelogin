package adaptors

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/kubeconfig"
)

//go:generate mockgen -package mock_adaptors -destination ../mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/adaptors/interfaces KubeConfig,HTTP,HTTPClientConfig,OIDC,Env,Logger

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type KubeConfig interface {
	LoadByDefaultRules(filename string) (*kubeconfig.Config, error)
	LoadFromFile(filename string) (*kubeconfig.Config, error)
	WriteToFile(config *kubeconfig.Config, filename string) error
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
	Authenticate(ctx context.Context, in OIDCAuthenticateIn, cb OIDCAuthenticateCallback) (*OIDCAuthenticateOut, error)
	VerifyIDToken(ctx context.Context, in OIDCVerifyTokenIn) (*oidc.IDToken, error)
}

type OIDCAuthenticateIn struct {
	Config          kubeconfig.OIDCConfig
	Client          *http.Client // HTTP client for oidc and oauth2
	LocalServerPort int          // HTTP server port
	SkipOpenBrowser bool         // skip opening browser if true
}

type OIDCAuthenticateCallback struct {
	ShowLocalServerURL func(url string)
}

type OIDCAuthenticateOut struct {
	VerifiedIDToken *oidc.IDToken
	IDToken         string
	RefreshToken    string
}

type OIDCVerifyTokenIn struct {
	Config kubeconfig.OIDCConfig
	Client *http.Client
}

type Env interface {
	Getenv(key string) string
}

type Logger interface {
	Printf(format string, v ...interface{})
	Debugf(level LogLevel, format string, v ...interface{})
	SetLevel(level LogLevel)
	IsEnabled(level LogLevel) bool
}

// LogLevel represents a log level for debug.
//
// 0 = None
// 1 = Including in/out
// 2 = Including transport headers
// 3 = Including transport body
//
type LogLevel int
