package usecases

import (
	"context"

	"github.com/int128/kubelogin/kubeconfig"
)

//go:generate mockgen -package mock_usecases -destination ../mock_usecases/mock_usecases.go github.com/int128/kubelogin/usecases/interfaces Login

type Login interface {
	Do(ctx context.Context, in LoginIn) error
}

type LoginIn struct {
	KubeConfigFilename           string                 // Default to the environment variable or global config as kubectl
	KubeContextName              kubeconfig.ContextName // Default to the current context but ignored if KubeUserName is set
	KubeUserName                 kubeconfig.UserName    // Default to the user of the context
	CertificateAuthorityFilename string                 // Optional
	SkipTLSVerify                bool
	SkipOpenBrowser              bool
	ListenPort                   []int
}
