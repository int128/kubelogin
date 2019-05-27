package usecases

import (
	"context"

	"github.com/int128/kubelogin/kubeconfig"
)

//go:generate mockgen -destination mock_usecases/mock_usecases.go github.com/int128/kubelogin/usecases Login

type Login interface {
	Do(ctx context.Context, in LoginIn) error
}

type LoginIn struct {
	KubeConfigFilename           string                 // Default to the environment variable or global config as kubectl
	KubeContextName              kubeconfig.ContextName // Default to the current context but ignored if KubeUserName is set
	KubeUserName                 kubeconfig.UserName    // Default to the user of the context
	SkipOpenBrowser              bool
	ListenPort                   []int
	Username                     string
	Password                     string
	CertificateAuthorityFilename string // Optional
	SkipTLSVerify                bool
}

type LoginPrompt interface {
	ShowLocalServerURL(url string)
}
