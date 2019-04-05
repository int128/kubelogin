package usecases

import "context"

//go:generate mockgen -package mock_usecases -destination ../mock_usecases/mock_usecases.go github.com/int128/kubelogin/usecases/interfaces Login

type Login interface {
	Do(ctx context.Context, in LoginIn) error
}

type LoginIn struct {
	KubeConfig      string
	SkipTLSVerify   bool
	SkipOpenBrowser bool
	ListenPort      int
}
