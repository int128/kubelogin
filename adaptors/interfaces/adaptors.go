package adaptors

import (
	"context"

	"k8s.io/client-go/tools/clientcmd/api"
)

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

type KubeConfig interface {
	LoadFromFile(filename string) (*api.Config, error)
	WriteToFile(config *api.Config, filename string) error
}
