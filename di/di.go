//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	adaptorsInterfaces "github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/usecases"
	"github.com/int128/kubelogin/usecases/login"
)

var usecasesSet = wire.NewSet(
	login.Login{},
	wire.Bind((*usecases.Login)(nil), (*login.Login)(nil)),
)

func NewCmd(logger adaptorsInterfaces.Logger) adaptorsInterfaces.Cmd {
	wire.Build(
		usecasesSet,
		adaptors.Set,
	)
	return nil
}
