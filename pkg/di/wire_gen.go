// Code generated by Wire. DO NOT EDIT.

//go:generate go run -mod=mod github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package di

import (
	"github.com/int128/kubelogin/pkg/cmd"
	reader2 "github.com/int128/kubelogin/pkg/credentialplugin/reader"
	writer2 "github.com/int128/kubelogin/pkg/credentialplugin/writer"
	"github.com/int128/kubelogin/pkg/infrastructure/browser"
	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/infrastructure/reader"
	"github.com/int128/kubelogin/pkg/infrastructure/stdio"
	loader2 "github.com/int128/kubelogin/pkg/kubeconfig/loader"
	"github.com/int128/kubelogin/pkg/kubeconfig/writer"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"github.com/int128/kubelogin/pkg/tlsclientconfig/loader"
	"github.com/int128/kubelogin/pkg/tokencache/repository"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/devicecode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/int128/kubelogin/pkg/usecases/clean"
	"github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/setup"
	"github.com/int128/kubelogin/pkg/usecases/standalone"
	"os"
)

// Injectors from di.go:

// NewCmd returns an instance of infrastructure.Cmd.
func NewCmd() cmd.Interface {
	clockReal := &clock.Real{}
	stdin := _wireFileValue
	stdout := _wireOsFileValue
	loggerInterface := logger.New()
	browserBrowser := &browser.Browser{}
	cmdInterface := NewCmdForHeadless(clockReal, stdin, stdout, loggerInterface, browserBrowser)
	return cmdInterface
}

var (
	_wireFileValue   = os.Stdin
	_wireOsFileValue = os.Stdout
)

// NewCmdForHeadless returns an instance of infrastructure.Cmd for headless testing.
func NewCmdForHeadless(clockInterface clock.Interface, stdin stdio.Stdin, stdout stdio.Stdout, loggerInterface logger.Interface, browserInterface browser.Interface) cmd.Interface {
	loaderLoader := loader.Loader{}
	factory := &client.Factory{
		Loader: loaderLoader,
		Clock:  clockInterface,
		Logger: loggerInterface,
	}
	authcodeBrowser := &authcode.Browser{
		Browser: browserInterface,
		Logger:  loggerInterface,
	}
	readerReader := &reader.Reader{
		Stdin: stdin,
	}
	keyboard := &authcode.Keyboard{
		Reader: readerReader,
		Logger: loggerInterface,
	}
	ropcROPC := &ropc.ROPC{
		Reader: readerReader,
		Logger: loggerInterface,
	}
	deviceCode := &devicecode.DeviceCode{
		Browser: browserInterface,
		Logger:  loggerInterface,
	}
	authenticationAuthentication := &authentication.Authentication{
		ClientFactory:    factory,
		Logger:           loggerInterface,
		AuthCodeBrowser:  authcodeBrowser,
		AuthCodeKeyboard: keyboard,
		ROPC:             ropcROPC,
		DeviceCode:       deviceCode,
	}
	loader3 := &loader2.Loader{}
	writerWriter := &writer.Writer{}
	standaloneStandalone := &standalone.Standalone{
		Authentication:   authenticationAuthentication,
		KubeconfigLoader: loader3,
		KubeconfigWriter: writerWriter,
		Logger:           loggerInterface,
		Clock:            clockInterface,
	}
	root := &cmd.Root{
		Standalone: standaloneStandalone,
		Logger:     loggerInterface,
	}
	repositoryRepository := &repository.Repository{}
	reader3 := &reader2.Reader{}
	writer3 := &writer2.Writer{
		Stdout: stdout,
	}
	getToken := &credentialplugin.GetToken{
		Authentication:         authenticationAuthentication,
		TokenCacheRepository:   repositoryRepository,
		CredentialPluginReader: reader3,
		CredentialPluginWriter: writer3,
		Logger:                 loggerInterface,
		Clock:                  clockInterface,
	}
	cmdGetToken := &cmd.GetToken{
		GetToken: getToken,
		Logger:   loggerInterface,
	}
	setupSetup := &setup.Setup{
		Authentication: authenticationAuthentication,
		Logger:         loggerInterface,
	}
	cmdSetup := &cmd.Setup{
		Setup: setupSetup,
	}
	cleanClean := &clean.Clean{
		TokenCacheRepository: repositoryRepository,
		Logger:               loggerInterface,
	}
	cmdClean := &cmd.Clean{
		Clean: cleanClean,
	}
	cmdCmd := &cmd.Cmd{
		Root:     root,
		GetToken: cmdGetToken,
		Setup:    cmdSetup,
		Clean:    cmdClean,
		Logger:   loggerInterface,
	}
	return cmdCmd
}
