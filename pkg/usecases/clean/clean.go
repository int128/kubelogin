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
	TokenCacheDir string
}

type Clean struct {
	TokenCacheRepository repository.Interface
	Logger               logger.Interface
}

func (u *Clean) Do(ctx context.Context, in Input) error {
	u.Logger.V(1).Infof("Deleting the token cache")

	if err := u.TokenCacheRepository.DeleteAll(tokencache.Config{Directory: in.TokenCacheDir, Storage: tokencache.StorageDisk}); err != nil {
		return fmt.Errorf("delete the token cache from %s: %w", in.TokenCacheDir, err)
	}
	u.Logger.Printf("Deleted the token cache from %s", in.TokenCacheDir)

	if err := u.TokenCacheRepository.DeleteAll(tokencache.Config{Directory: in.TokenCacheDir, Storage: tokencache.StorageKeyring}); err != nil {
		// Do not return an error because the keyring may not be available.
		u.Logger.Printf("Could not delete the token cache from the keyring: %s", err)
	} else {
		u.Logger.Printf("Deleted the token cache from the keyring")
	}
	return nil
}
