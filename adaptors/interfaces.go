package adaptors

import (
	"context"
	"time"

	"github.com/int128/kubelogin/models/kubeconfig"
)

//go:generate mockgen -destination mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/adaptors Kubeconfig,OIDC,OIDCClient,Env,Logger

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type Kubeconfig interface {
	GetCurrentAuthProvider(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error)
	UpdateAuthProvider(auth *kubeconfig.AuthProvider) error
}

type OIDC interface {
	New(ctx context.Context, config OIDCClientConfig) (OIDCClient, error)
}

type OIDCClientConfig struct {
	Config         kubeconfig.OIDCConfig
	CACertFilename string
	SkipTLSVerify  bool
}

type OIDCClient interface {
	AuthenticateByCode(ctx context.Context, in OIDCAuthenticateByCodeIn) (*OIDCAuthenticateOut, error)
	AuthenticateByPassword(ctx context.Context, in OIDCAuthenticateByPasswordIn) (*OIDCAuthenticateOut, error)
	Verify(ctx context.Context, in OIDCVerifyIn) (*OIDCVerifyOut, error)
	Refresh(ctx context.Context, in OIDCRefreshIn) (*OIDCAuthenticateOut, error)
}

type OIDCAuthenticateByCodeIn struct {
	LocalServerPort    []int // HTTP server port candidates
	SkipOpenBrowser    bool  // skip opening browser if true
	ShowLocalServerURL interface{ ShowLocalServerURL(url string) }
}

type OIDCAuthenticateByPasswordIn struct {
	Username string
	Password string
}

type OIDCAuthenticateOut struct {
	IDToken       string
	RefreshToken  string
	IDTokenExpiry time.Time
	IDTokenClaims map[string]string // string representation of claims for logging
}

type OIDCVerifyIn struct {
	IDToken      string
	RefreshToken string
}

type OIDCVerifyOut struct {
	IDTokenExpiry time.Time
	IDTokenClaims map[string]string // string representation of claims for logging
}

type OIDCRefreshIn struct {
	RefreshToken string
}

type Env interface {
	ReadPassword(prompt string) (string, error)
	Exec(ctx context.Context, executable string, args []string) (int, error)
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
