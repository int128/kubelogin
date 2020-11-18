//+build wireinject

// Package di provides dependency injection.
package di

import (
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/browser"
	"github.com/int128/kubelogin/pkg/adaptors/clock"
	"github.com/int128/kubelogin/pkg/adaptors/cmd"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/mutex"
	"github.com/int128/kubelogin/pkg/adaptors/oidcclient"
	"github.com/int128/kubelogin/pkg/adaptors/reader"
	"github.com/int128/kubelogin/pkg/adaptors/stdio"
	"github.com/int128/kubelogin/pkg/credentialplugin/writer"
	kubeconfigLoader "github.com/int128/kubelogin/pkg/kubeconfig/loader"
	kubeconfigWriter "github.com/int128/kubelogin/pkg/kubeconfig/writer"
	"github.com/int128/kubelogin/pkg/tlsclientconfig/loader"
	"github.com/int128/kubelogin/pkg/tokencache/repository"
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
		clock.Set,
		stdio.Set,
		logger.Set,
		browser.Set,
	)
	return nil
}

// NewCmdForHeadless returns an instance of adaptors.Cmd for headless testing.
func NewCmdForHeadless(clock.Interface, stdio.Stdin, stdio.Stdout, logger.Interface, browser.Interface) cmd.Interface {
	wire.Build(
		// use-cases
		authentication.Set,
		standalone.Set,
		credentialplugin.Set,
		setup.Set,

		// adaptors
		cmd.Set,
		reader.Set,
		kubeconfigLoader.Set,
		kubeconfigWriter.Set,
		repository.Set,
		oidcclient.Set,
		loader.Set,
		writer.Set,
		mutex.Set,
	)
	return nil
}
