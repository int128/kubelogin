//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/pipedrive/kubelogin/pkg/adaptors/certpool"
	"github.com/pipedrive/kubelogin/pkg/adaptors/cmd"
	credentialPluginAdaptor "github.com/pipedrive/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/pipedrive/kubelogin/pkg/adaptors/env"
	"github.com/pipedrive/kubelogin/pkg/adaptors/jwtdecoder"
	"github.com/pipedrive/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/pipedrive/kubelogin/pkg/adaptors/logger"
	"github.com/pipedrive/kubelogin/pkg/adaptors/oidcclient"
	"github.com/pipedrive/kubelogin/pkg/adaptors/tokencache"
	"github.com/pipedrive/kubelogin/pkg/usecases/authentication"
	credentialPluginUseCase "github.com/pipedrive/kubelogin/pkg/usecases/credentialplugin"
	"github.com/pipedrive/kubelogin/pkg/usecases/setup"
	"github.com/pipedrive/kubelogin/pkg/usecases/standalone"
)

// NewCmd returns an instance of adaptors.Cmd.
func NewCmd() cmd.Interface {
	wire.Build(
		// use-cases
		authentication.Set,
		wire.Value(authentication.DefaultLocalServerReadyFunc),
		standalone.Set,
		credentialPluginUseCase.Set,
		setup.Set,

		// adaptors
		cmd.Set,
		env.Set,
		kubeconfig.Set,
		tokencache.Set,
		credentialPluginAdaptor.Set,
		oidcclient.Set,
		jwtdecoder.Set,
		certpool.Set,
		logger.Set,
	)
	return nil
}

// NewCmdForHeadless returns an instance of adaptors.Cmd for headless testing.
func NewCmdForHeadless(logger.Interface, authentication.LocalServerReadyFunc, credentialPluginAdaptor.Interface) cmd.Interface {
	wire.Build(
		authentication.Set,
		standalone.Set,
		credentialPluginUseCase.Set,
		setup.Set,

		cmd.Set,
		env.Set,
		kubeconfig.Set,
		tokencache.Set,
		oidcclient.Set,
		jwtdecoder.Set,
		certpool.Set,
	)
	return nil
}
