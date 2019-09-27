// Package setup provides the use case of setting up environment.
package setup

import (
	"context"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/adaptors/logger"
	"github.com/int128/kubelogin/pkg/usecases/auth"
)

var Set = wire.NewSet(
	wire.Struct(new(Setup), "*"),
	wire.Bind(new(Interface), new(*Setup)),
)

type Interface interface {
	DoStage1()
	DoStage2(ctx context.Context, in Stage2Input) error
}

type Setup struct {
	Authentication auth.Interface
	Logger         logger.Interface
}
