package clean

import (
	"context"
	"fmt"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/tokencache"
	"github.com/int128/kubelogin/pkg/tokencache/repository"
)

var Set = wire.NewSet(
	wire.Struct(new(Clean), "*"),
	wire.Bind(new(Interface), new(*Clean)),
)

type Interface interface {
	Do(ctx context.Context, in Input) error
}

// Input represents an input of the Clean use-case.
type Input struct {
	TokenCacheConfig tokencache.Config
}

type Clean struct {
	TokenCacheRepository repository.Interface
	Logger               logger.Interface
}

func (u *Clean) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("Deleting the token cache")
	if err := u.TokenCacheRepository.DeleteAll(in.TokenCacheConfig); err != nil {
		return fmt.Errorf("delete the token cache: %w", err)
	}
	u.Logger.Printf("Deleted the token cache")
	return nil
}
