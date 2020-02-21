// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package di

import (
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

// Injectors from di.go:

func NewCmd() cmd.Interface {
	loggerInterface := logger.New()
	browserBrowser := &browser.Browser{}
	writer := &credentialpluginwriter.Writer{}
	cmdInterface := NewCmdForHeadless(loggerInterface, browserBrowser, writer)
	return cmdInterface
}

func NewCmdForHeadless(loggerInterface logger.Interface, browserInterface browser.Interface, credentialpluginwriterInterface credentialpluginwriter.Interface) cmd.Interface {
	newFunc := _wireNewFuncValue
	envEnv := &env.Env{}
	authCode := &authentication.AuthCode{
		Env:     envEnv,
		Browser: browserInterface,
		Logger:  loggerInterface,
	}
	authCodeKeyboard := &authentication.AuthCodeKeyboard{
		Env:    envEnv,
		Logger: loggerInterface,
	}
	ropc := &authentication.ROPC{
		Env:    envEnv,
		Logger: loggerInterface,
	}
	authenticationAuthentication := &authentication.Authentication{
		NewOIDCClient:    newFunc,
		Logger:           loggerInterface,
		Env:              envEnv,
		AuthCode:         authCode,
		AuthCodeKeyboard: authCodeKeyboard,
		ROPC:             ropc,
	}
	kubeconfigKubeconfig := &kubeconfig.Kubeconfig{
		Logger: loggerInterface,
	}
	certpoolNewFunc := _wireCertpoolNewFuncValue
	standaloneStandalone := &standalone.Standalone{
		Authentication: authenticationAuthentication,
		Kubeconfig:     kubeconfigKubeconfig,
		NewCertPool:    certpoolNewFunc,
		Logger:         loggerInterface,
	}
	root := &cmd.Root{
		Standalone: standaloneStandalone,
		Logger:     loggerInterface,
	}
	repository := &tokencache.Repository{}
	getToken := &credentialplugin.GetToken{
		Authentication:       authenticationAuthentication,
		TokenCacheRepository: repository,
		NewCertPool:          certpoolNewFunc,
		Writer:               credentialpluginwriterInterface,
		Logger:               loggerInterface,
	}
	cmdGetToken := &cmd.GetToken{
		GetToken: getToken,
		Logger:   loggerInterface,
	}
	setupSetup := &setup.Setup{
		Authentication: authenticationAuthentication,
		NewCertPool:    certpoolNewFunc,
		Logger:         loggerInterface,
	}
	cmdSetup := &cmd.Setup{
		Setup: setupSetup,
	}
	cmdCmd := &cmd.Cmd{
		Root:     root,
		GetToken: cmdGetToken,
		Setup:    cmdSetup,
		Logger:   loggerInterface,
	}
	return cmdCmd
}

var (
	_wireNewFuncValue         = oidcclient.NewFunc(oidcclient.New)
	_wireCertpoolNewFuncValue = certpool.NewFunc(certpool.New)
)
