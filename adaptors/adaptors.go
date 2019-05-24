package adaptors

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/kubeconfig"
)

//go:generate mockgen -destination mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/adaptors KubeConfig,HTTP,OIDC,OIDCClient,Logger

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type KubeConfig interface {
	LoadByDefaultRules(filename string) (*kubeconfig.Config, error)
	LoadFromFile(filename string) (*kubeconfig.Config, error)
	WriteToFile(config *kubeconfig.Config, filename string) error
}

type HTTP interface {
	NewClient(config HTTPClientConfig) (*http.Client, error)
}

type HTTPClientConfig struct {
	OIDCConfig                   kubeconfig.OIDCConfig
	CertificateAuthorityFilename string
	SkipTLSVerify                bool
}

type OIDC interface {
	NewClient(config HTTPClientConfig) (OIDCClient, error)
}

type OIDCClient interface {
	AuthenticateByCode(ctx context.Context, in OIDCAuthenticateByCodeIn, cb OIDCAuthenticateCallback) (*OIDCAuthenticateOut, error)
	AuthenticateByPassword(ctx context.Context, in OIDCAuthenticateByPasswordIn) (*OIDCAuthenticateOut, error)
	Verify(ctx context.Context, in OIDCVerifyIn) (*oidc.IDToken, error)
}

type OIDCAuthenticateByCodeIn struct {
	Config          kubeconfig.OIDCConfig
	LocalServerPort []int // HTTP server port candidates
	SkipOpenBrowser bool  // skip opening browser if true
}

type OIDCAuthenticateByPasswordIn struct {
	Config   kubeconfig.OIDCConfig
	Username string
	Password string
}

type OIDCAuthenticateCallback struct {
	ShowLocalServerURL func(url string)
}

type OIDCAuthenticateOut struct {
	VerifiedIDToken *oidc.IDToken
	IDToken         string
	RefreshToken    string
}

type OIDCVerifyIn struct {
	Config kubeconfig.OIDCConfig
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
