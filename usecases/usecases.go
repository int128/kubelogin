// Package usecases provides use-cases.
package usecases

import (
	"github.com/google/wire"
	usecases "github.com/int128/kubelogin/usecases/interfaces"
)

var Set = wire.NewSet(
	Login{},
	wire.Bind((*usecases.Login)(nil), (*Login)(nil)),
)
