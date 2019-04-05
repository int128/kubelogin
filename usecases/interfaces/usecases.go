package usecases

import "context"

type Login interface {
	Do(ctx context.Context, in LoginIn) error
}

type LoginIn struct {
	KubeConfig      string
	SkipTLSVerify   bool
	SkipOpenBrowser bool
	ListenPort      int
}
