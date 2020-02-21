//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/certpool"
	"github.com/int128/kubelogin/pkg/adaptors/cmd"
	"github.com/int128/kubelogin/pkg/adaptors/credentialpluginwriter"
	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/setup"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
)

// NewCmd returns an instance of adaptors.Cmd.
func NewCmd() cmd.Interface {
	wire.Build(
		NewCmdForHeadless,

		// dependencies for production
		logger.Set,
		browser.Set,
		credentialpluginwriter.Set,
	)
	return nil
}

// NewCmdForHeadless returns an instance of adaptors.Cmd for headless testing.
func NewCmdForHeadless(logger.Interface, browser.Interface, credentialpluginwriter.Interface) cmd.Interface {
	wire.Build(
		// use-cases
		authentication.Set,
		standalone.Set,
		credentialplugin.Set,
		setup.Set,

		// adaptors
		cmd.Set,
		env.Set,
		kubeconfig.Set,
		tokencache.Set,
		oidcclient.Set,
		certpool.Set,
	)
	return nil
}
