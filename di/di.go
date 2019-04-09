// Package di provides dependency injection.
package di

import (
	"github.com/int128/kubelogin/adaptors"
	adaptorsInterfaces "github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/usecases"
)

// Invoke runs the function with an adaptors.Cmd instance.
func Invoke(f func(cmd adaptorsInterfaces.Cmd)) error {
	f(&adaptors.Cmd{
		Login: &usecases.Login{
			KubeConfig: &adaptors.KubeConfig{},
			HTTP:       &adaptors.HTTP{},
			OIDC:       &adaptors.OIDC{},
			Logger:     &adaptors.Logger{},
		},
		Logger: &adaptors.Logger{},
	})
	return nil
}
