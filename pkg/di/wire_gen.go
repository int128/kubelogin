// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package di

import (
	"github.com/int128/kubelogin/pkg/adaptors"
	"github.com/int128/kubelogin/pkg/adaptors/cmd"
	"github.com/int128/kubelogin/pkg/adaptors/credentialplugin"
	"github.com/int128/kubelogin/pkg/adaptors/env"
	"github.com/int128/kubelogin/pkg/adaptors/kubeconfig"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/adaptors/oidc"
	"github.com/int128/kubelogin/pkg/adaptors/tokencache"
	"github.com/int128/kubelogin/pkg/usecases"
	"github.com/int128/kubelogin/pkg/usecases/auth"
	credentialplugin2 "github.com/int128/kubelogin/pkg/usecases/credentialplugin"
	"github.com/int128/kubelogin/pkg/usecases/login"
)

// Injectors from di.go:

func NewCmd() adaptors.Cmd {
	loggerInterface := logger.New()
	factory := &oidc.Factory{
		Logger: loggerInterface,
	}
	decoder := &oidc.Decoder{}
	envEnv := &env.Env{}
	showLocalServerURL := &auth.ShowLocalServerURL{
		Logger: loggerInterface,
	}
	authentication := &auth.Authentication{
		OIDCFactory:        factory,
		OIDCDecoder:        decoder,
		Env:                envEnv,
		Logger:             loggerInterface,
		ShowLocalServerURL: showLocalServerURL,
	}
	kubeconfigKubeconfig := &kubeconfig.Kubeconfig{}
	loginLogin := &login.Login{
		Authentication: authentication,
		Kubeconfig:     kubeconfigKubeconfig,
		Logger:         loggerInterface,
	}
	root := &cmd.Root{
		Login:  loginLogin,
		Logger: loggerInterface,
	}
	repository := &tokencache.Repository{}
	interaction := &credentialplugin.Interaction{}
	getToken := &credentialplugin2.GetToken{
		Authentication:       authentication,
		TokenCacheRepository: repository,
		Interaction:          interaction,
		Logger:               loggerInterface,
	}
	cmdGetToken := &cmd.GetToken{
		GetToken: getToken,
		Logger:   loggerInterface,
	}
	cmdCmd := &cmd.Cmd{
		Root:     root,
		GetToken: cmdGetToken,
		Logger:   loggerInterface,
	}
	return cmdCmd
}

func NewCmdForHeadless(loggerInterface logger.Interface, loginShowLocalServerURL usecases.LoginShowLocalServerURL, credentialpluginInterface credentialplugin.Interface) adaptors.Cmd {
	factory := &oidc.Factory{
		Logger: loggerInterface,
	}
	decoder := &oidc.Decoder{}
	envEnv := &env.Env{}
	authentication := &auth.Authentication{
		OIDCFactory:        factory,
		OIDCDecoder:        decoder,
		Env:                envEnv,
		Logger:             loggerInterface,
		ShowLocalServerURL: loginShowLocalServerURL,
	}
	kubeconfigKubeconfig := &kubeconfig.Kubeconfig{}
	loginLogin := &login.Login{
		Authentication: authentication,
		Kubeconfig:     kubeconfigKubeconfig,
		Logger:         loggerInterface,
	}
	root := &cmd.Root{
		Login:  loginLogin,
		Logger: loggerInterface,
	}
	repository := &tokencache.Repository{}
	getToken := &credentialplugin2.GetToken{
		Authentication:       authentication,
		TokenCacheRepository: repository,
		Interaction:          credentialpluginInterface,
		Logger:               loggerInterface,
	}
	cmdGetToken := &cmd.GetToken{
		GetToken: getToken,
		Logger:   loggerInterface,
	}
	cmdCmd := &cmd.Cmd{
		Root:     root,
		GetToken: cmdGetToken,
		Logger:   loggerInterface,
	}
	return cmdCmd
}
