//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/adaptors/cmd"
	credentialPluginAdaptor "github.com/int128/kubelogin/adaptors/credentialplugin"
	"github.com/int128/kubelogin/adaptors/env"
	"github.com/int128/kubelogin/adaptors/kubeconfig"
	"github.com/int128/kubelogin/adaptors/logger"
	"github.com/int128/kubelogin/adaptors/oidc"
	"github.com/int128/kubelogin/adaptors/tokencache"
	"github.com/int128/kubelogin/usecases"
	"github.com/int128/kubelogin/usecases/auth"
	credentialPluginUseCase "github.com/int128/kubelogin/usecases/credentialplugin"
	"github.com/int128/kubelogin/usecases/login"
)

// NewCmd returns an instance of adaptors.Cmd.
func NewCmd() adaptors.Cmd {
	wire.Build(
		auth.Set,
		auth.ExtraSet,
		login.Set,
		credentialPluginUseCase.Set,
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
func NewCmdForHeadless(
	adaptors.Logger,
	usecases.LoginShowLocalServerURL,
	adaptors.CredentialPluginInteraction,
) adaptors.Cmd {
	wire.Build(
		auth.Set,
		login.Set,
		credentialPluginUseCase.Set,
		cmd.Set,
		env.Set,
		kubeconfig.Set,
		tokencache.Set,
		oidc.Set,
	)
	return nil
}
