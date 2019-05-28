//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/cmd"
	"github.com/int128/kubelogin/adaptors/http"
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
	http.HTTP{},
	kubeconfig.KubeConfig{},
	oidc.OIDC{},
	wire.Bind((*adaptors.Cmd)(nil), (*cmd.Cmd)(nil)),
	wire.Bind((*adaptors.HTTP)(nil), (*http.HTTP)(nil)),
	wire.Bind((*adaptors.KubeConfig)(nil), (*kubeconfig.KubeConfig)(nil)),
	wire.Bind((*adaptors.OIDC)(nil), (*oidc.OIDC)(nil)),
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
