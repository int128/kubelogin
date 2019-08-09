package usecases

import (
	"context"
	"time"

	"github.com/int128/kubelogin/pkg/models/kubeconfig"
)

//go:generate mockgen -destination mock_usecases/mock_usecases.go github.com/int128/kubelogin/pkg/usecases Login,GetToken,Authentication

type Login interface {
	Do(ctx context.Context, in LoginIn) error
}

// LoginIn represents an input DTO of the Login use-case.
type LoginIn struct {
	KubeconfigFilename string                 // Default to the environment variable or global config as kubectl
	KubeconfigContext  kubeconfig.ContextName // Default to the current context but ignored if KubeconfigUser is set
	KubeconfigUser     kubeconfig.UserName    // Default to the user of the context
	SkipOpenBrowser    bool
	ListenPort         []int
	Username           string // If set, perform the resource owner password credentials grant
	Password           string // If empty, read a password using Env.ReadPassword()
	CACertFilename     string // If set, use the CA cert
	SkipTLSVerify      bool
}

// LoginShowLocalServerURL provides an interface to notify the URL of local server.
// It is needed for the end-to-end tests.
type LoginShowLocalServerURL interface {
	ShowLocalServerURL(url string)
}

type GetToken interface {
	Do(ctx context.Context, in GetTokenIn) error
}

// GetTokenIn represents an input DTO of the GetToken use-case.
type GetTokenIn struct {
	IssuerURL          string
	ClientID           string
	ClientSecret       string
	ExtraScopes        []string // optional
	SkipOpenBrowser    bool
	ListenPort         []int
	Username           string // If set, perform the resource owner password credentials grant
	Password           string // If empty, read a password using Env.ReadPassword()
	CACertFilename     string // If set, use the CA cert
	SkipTLSVerify      bool
	TokenCacheFilename string
}

type Authentication interface {
	Do(ctx context.Context, in AuthenticationIn) (*AuthenticationOut, error)
}

// AuthenticationIn represents an input DTO of the Authentication use-case.
type AuthenticationIn struct {
	OIDCConfig      kubeconfig.OIDCConfig
	SkipOpenBrowser bool
	ListenPort      []int
	Username        string // If set, perform the resource owner password credentials grant
	Password        string // If empty, read a password using Env.ReadPassword()
	CACertFilename  string // If set, use the CA cert
	SkipTLSVerify   bool
}

// AuthenticationIn represents an output DTO of the Authentication use-case.
type AuthenticationOut struct {
	AlreadyHasValidIDToken bool
	IDTokenExpiry          time.Time
	IDTokenClaims          map[string]string
	IDToken                string
	RefreshToken           string
}
