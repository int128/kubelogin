//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/cmd"
	"github.com/int128/kubelogin/adaptors/env"
	"github.com/int128/kubelogin/adaptors/kubeconfig"
	"github.com/int128/kubelogin/adaptors/logger"
	"github.com/int128/kubelogin/adaptors/oidc"
	"github.com/int128/kubelogin/usecases"
	"github.com/int128/kubelogin/usecases/auth"
	"github.com/int128/kubelogin/usecases/login"
)

func NewCmd() adaptors.Cmd {
	wire.Build(
		auth.Set,
		auth.ExtraSet,
		login.Set,
		cmd.Set,
		env.Set,
		kubeconfig.Set,
		oidc.Set,
		logger.Set,
	)
	return nil
}

func NewCmdWith(adaptors.Logger, usecases.LoginShowLocalServerURL) adaptors.Cmd {
	wire.Build(
		auth.Set,
		login.Set,
		cmd.Set,
		env.Set,
		kubeconfig.Set,
		oidc.Set,
	)
	return nil
}
