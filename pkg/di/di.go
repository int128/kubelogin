//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/cmd"
	credentialPluginAdaptor "github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidc"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/usecases/auth"
	credentialPluginUseCase "github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/setup"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
)

// NewCmd returns an instance of adaptors.Cmd.
func NewCmd() cmd.Interface {
	wire.Build(
		// use-cases
		auth.Set,
		wire.Value(auth.DefaultLocalServerReadyFunc),
		standalone.Set,
		credentialPluginUseCase.Set,
		setup.Set,

		// adaptors
		cmd.Set,
		env.Set,
		kubeconfig.Set,
		tokencache.Set,
		credentialPluginAdaptor.Set,
		oidc.Set,
		logger.Set,
	)
	return nil
}

// NewCmdForHeadless returns an instance of adaptors.Cmd for headless testing.
func NewCmdForHeadless(logger.Interface, auth.LocalServerReadyFunc, credentialPluginAdaptor.Interface) cmd.Interface {
	wire.Build(
		auth.Set,
		standalone.Set,
		credentialPluginUseCase.Set,
		setup.Set,

		cmd.Set,
		env.Set,
		kubeconfig.Set,
		tokencache.Set,
		oidc.Set,
	)
	return nil
}
