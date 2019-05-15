// Package di provides dependency injection.
package di

import (
	"github.com/int128/kubelogin/adaptors"
	adaptorsInterfaces "github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/usecases"
	"github.com/pkg/errors"
	"go.uber.org/dig"
)

var constructors = []interface{}{
	usecases.NewLogin,

	adaptors.NewCmd,
	adaptors.NewKubeConfig,
	adaptors.NewOIDC,
	adaptors.NewHTTP,
}

var extraConstructors = []interface{}{
	adaptors.NewLogger,
}

// Invoke runs the function with the default constructors.
func Invoke(f func(cmd adaptorsInterfaces.Cmd)) error {
	return InvokeWithExtra(f, extraConstructors...)
}

// InvokeWithExtra runs the function with the given constructors.
func InvokeWithExtra(f func(cmd adaptorsInterfaces.Cmd), extra ...interface{}) error {
	c := dig.New()
	for _, constructor := range append(constructors, extra...) {
		if err := c.Provide(constructor); err != nil {
			return errors.Wrapf(err, "could not provide the constructor")
		}
	}
	if err := c.Invoke(f); err != nil {
		return errors.Wrapf(err, "could not invoke")
	}
	return nil
}
