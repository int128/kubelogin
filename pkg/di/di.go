//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors"
	"github.com/int128/kubelogin/pkg/adaptors/cmd"
	credentialPluginAdaptor "github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidc"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/usecases"
	"github.com/int128/kubelogin/pkg/usecases/auth"
	credentialPluginUseCase "github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/login"
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
