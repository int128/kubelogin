package adaptors

import (
	"context"
	"time"

	"github.com/int128/kubelogin/pkg/models/credentialplugin"
	"github.com/int128/kubelogin/pkg/models/kubeconfig"
	"github.com/spf13/pflag"
)

//go:generate mockgen -destination mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/pkg/adaptors Kubeconfig,TokenCacheRepository,CredentialPluginInteraction,OIDC,OIDCClient,OIDCDecoder,Env,Logger

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type Kubeconfig interface {
	GetCurrentAuthProvider(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error)
	UpdateAuthProvider(auth *kubeconfig.AuthProvider) error
}

type TokenCacheRepository interface {
	FindByKey(dir string, key credentialplugin.TokenCacheKey) (*credentialplugin.TokenCache, error)
	Save(dir string, key credentialplugin.TokenCacheKey, cache credentialplugin.TokenCache) error
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

// OIDCRefreshIn represents an input DTO of OIDCClient.Refresh.
type OIDCRefreshIn struct {
	RefreshToken string
}

type OIDCDecoder interface {
	DecodeIDToken(t string) (*DecodedIDToken, error)
}

type DecodedIDToken struct {
	IDTokenExpiry time.Time
	IDTokenClaims map[string]string // string representation of claims for logging
}

type Env interface {
	ReadPassword(prompt string) (string, error)
}

type Logger interface {
	AddFlags(f *pflag.FlagSet)
	Printf(format string, args ...interface{})
	V(level int) Verbose
	IsEnabled(level int) bool
}

type Verbose interface {
	Infof(format string, args ...interface{})
}

// LogLevel represents a log level for debug.
//
// 0 = None
// 1 = Including in/out
// 2 = Including transport headers
// 3 = Including transport body
//
type LogLevel int
