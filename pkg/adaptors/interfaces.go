package adaptors

import (
	"context"

	"github.com/int128/kubelogin/pkg/models/kubeconfig"
)

//go:generate mockgen -destination mock_adaptors/mock_adaptors.go github.com/int128/kubelogin/pkg/adaptors Kubeconfig

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type Kubeconfig interface {
	GetCurrentAuthProvider(explicitFilename string, contextName kubeconfig.ContextName, userName kubeconfig.UserName) (*kubeconfig.AuthProvider, error)
	UpdateAuthProvider(auth *kubeconfig.AuthProvider) error
}

// LogLevel represents a log level for debug.
//
// 0 = None
// 1 = Including in/out
// 2 = Including transport headers
// 3 = Including transport body
//
type LogLevel int
