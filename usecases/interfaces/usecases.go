package usecases

import (
	"context"

	"k8s.io/client-go/tools/clientcmd/api"
)

type Login interface {
	Do(ctx context.Context, in LoginIn) error
}

type LoginIn struct {
	Config          api.Config
	ConfigPath      string
	SkipTLSVerify   bool
	SkipOpenBrowser bool
	ListenPort      int
}
