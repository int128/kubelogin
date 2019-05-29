//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/cmd"
	"github.com/int128/kubelogin/adaptors/kubeconfig"
	"github.com/int128/kubelogin/adaptors/logger"
	"github.com/int128/kubelogin/adaptors/oidc"
	"github.com/int128/kubelogin/usecases"
	"github.com/int128/kubelogin/usecases/login"
)

var usecasesSet = wire.NewSet(
	login.Login{},
	wire.Bind((*usecases.Login)(nil), (*login.Login)(nil)),
)

var adaptorsSet = wire.NewSet(
	cmd.Cmd{},
	kubeconfig.Kubeconfig{},
	oidc.Factory{},
	wire.Bind((*adaptors.Cmd)(nil), (*cmd.Cmd)(nil)),
	wire.Bind((*adaptors.Kubeconfig)(nil), (*kubeconfig.Kubeconfig)(nil)),
	wire.Bind((*adaptors.OIDC)(nil), (*oidc.Factory)(nil)),
)

var extraSet = wire.NewSet(
	login.Prompt{},
	wire.Bind((*usecases.LoginPrompt)(nil), (*login.Prompt)(nil)),
	logger.New,
)

func NewCmd() adaptors.Cmd {
	wire.Build(
		usecasesSet,
		adaptorsSet,
		extraSet,
	)
	return nil
}

func NewCmdWith(adaptors.Logger, usecases.LoginPrompt) adaptors.Cmd {
	wire.Build(
		usecasesSet,
		adaptorsSet,
	)
	return nil
}
