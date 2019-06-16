package usecases

import (
	"context"

	"github.com/int128/kubelogin/models/kubeconfig"
)

//go:generate mockgen -destination mock_usecases/mock_usecases.go github.com/int128/kubelogin/usecases Login,LoginAndExec

type Login interface {
	Do(ctx context.Context, in LoginIn) error
}

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

type LoginAndExec interface {
	Do(ctx context.Context, in LoginAndExecIn) (*LoginAndExecOut, error)
}

type LoginAndExecIn struct {
	LoginIn    LoginIn
	Executable string
	Args       []string
}

type LoginAndExecOut struct {
	ExitCode int
}
