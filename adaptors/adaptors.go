package adaptors

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/int128/kubelogin/models/kubeconfig"
)

//go:generate mockgen -destination mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/adaptors Kubeconfig,OIDC,OIDCClient,Env,Logger

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type Kubeconfig interface {
	GetCurrentAuth(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.Auth, error)
	UpdateAuth(auth *kubeconfig.Auth) error
}

type OIDC interface {
	New(config OIDCClientConfig) (OIDCClient, error)
}

type OIDCClientConfig struct {
	Config         kubeconfig.OIDCConfig
	CACertFilename string
	SkipTLSVerify  bool
}

type OIDCClient interface {
	AuthenticateByCode(ctx context.Context, in OIDCAuthenticateByCodeIn) (*OIDCAuthenticateOut, error)
	AuthenticateByPassword(ctx context.Context, in OIDCAuthenticateByPasswordIn) (*OIDCAuthenticateOut, error)
	Verify(ctx context.Context, in OIDCVerifyIn) (*oidc.IDToken, error)
}

type OIDCAuthenticateByCodeIn struct {
	Config          kubeconfig.OIDCConfig
	LocalServerPort []int // HTTP server port candidates
	SkipOpenBrowser bool  // skip opening browser if true
	Prompt          OIDCAuthenticateByCodePrompt
}

type OIDCAuthenticateByCodePrompt interface {
	ShowLocalServerURL(url string)
}

type OIDCAuthenticateByPasswordIn struct {
	Config   kubeconfig.OIDCConfig
	Username string
	Password string
}

type OIDCAuthenticateOut struct {
	VerifiedIDToken *oidc.IDToken
	IDToken         string
	RefreshToken    string
}

type OIDCVerifyIn struct {
	Config kubeconfig.OIDCConfig
}

type Env interface {
	ReadPassword(prompt string) (string, error)
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
