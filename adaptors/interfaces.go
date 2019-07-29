package adaptors

import (
	"context"
	"time"

	"github.com/int128/kubelogin/models/credentialplugin"
	"github.com/int128/kubelogin/models/kubeconfig"
)

//go:generate mockgen -destination mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/adaptors Kubeconfig,TokenCacheRepository,CredentialPluginInteraction,OIDC,OIDCClient,Env,Logger

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type Kubeconfig interface {
	GetCurrentAuthProvider(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error)
	UpdateAuthProvider(auth *kubeconfig.AuthProvider) error
}

type TokenCacheRepository interface {
	Read(filename string) (*credentialplugin.TokenCache, error)
	Write(filename string, tc credentialplugin.TokenCache) error
}

type CredentialPluginInteraction interface {
	Write(out credentialplugin.Output) error
}

type OIDC interface {
	New(ctx context.Context, config OIDCClientConfig) (OIDCClient, error)
}

// OIDCClientConfig represents a configuration of an OIDCClient to create.
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

// OIDCAuthenticateByCodeIn represents an input DTO of OIDCClient.AuthenticateByCode.
type OIDCAuthenticateByCodeIn struct {
	LocalServerPort    []int // HTTP server port candidates
	SkipOpenBrowser    bool  // skip opening browser if true
	ShowLocalServerURL interface{ ShowLocalServerURL(url string) }
}

// OIDCAuthenticateByPasswordIn represents an input DTO of OIDCClient.AuthenticateByPassword.
type OIDCAuthenticateByPasswordIn struct {
	Username string
	Password string
}

// OIDCAuthenticateOut represents an output DTO of
// OIDCClient.AuthenticateByCode, OIDCClient.AuthenticateByPassword and OIDCClient.Refresh.
type OIDCAuthenticateOut struct {
	IDToken       string
	RefreshToken  string
	IDTokenExpiry time.Time
	IDTokenClaims map[string]string // string representation of claims for logging
}

// OIDCVerifyIn represents an input DTO of OIDCClient.Verify.
type OIDCVerifyIn struct {
	IDToken      string
	RefreshToken string
}

// OIDCVerifyIn represents an output DTO of OIDCClient.Verify.
type OIDCVerifyOut struct {
	IDTokenExpiry time.Time
	IDTokenClaims map[string]string // string representation of claims for logging
}

// OIDCRefreshIn represents an input DTO of OIDCClient.Refresh.
type OIDCRefreshIn struct {
	RefreshToken string
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
