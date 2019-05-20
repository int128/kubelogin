//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	adaptorsInterfaces "github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/usecases"
)

func NewCmd(logger adaptorsInterfaces.Logger) adaptorsInterfaces.Cmd {
	wire.Build(
		usecases.Set,
		adaptors.Set,
	)
	return nil
}
