package mutex

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/alexflint/go-filemutex"
	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
)

var Set = wire.NewSet(
	wire.Struct(new(Mutex), "*"),
	wire.Bind(new(Interface), new(*Mutex)),
)

type Interface interface {
	Acquire(ctx context.Context, name string) (*Lock, error)
	Release(lock *Lock) error
}

// Lock holds the lock data.
type Lock struct {
	Data interface{}
	Name string
}

type Mutex struct {
	Logger logger.Interface
}

// internalAcquire wait for acquisition of the lock
func internalAcquire(fm *filemutex.FileMutex) chan error {
	result := make(chan error)
	go func() {
		if err := fm.Lock(); err != nil {
			result <- err
		}
		close(result)
	}()
	return result
}

// internalRelease disposes of resources associated with a lock
func internalRelease(fm *filemutex.FileMutex, lfn string, log logger.Interface) error {
	err := fm.Close()
	if err != nil {
		log.V(1).Infof("Error closing lock file %s: %s", lfn, err)
	}
	return err
}

// LockFileName get the lock file name from the lock name.
func LockFileName(name string) string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		dirname = os.TempDir()
	}
	return path.Join(dirname, fmt.Sprintf(".kubelogin.%s.lock", name))
}

// Acquire acquire a lock for the specified name. The context could be used to set a timeout.
func (m *Mutex) Acquire(ctx context.Context, name string) (*Lock, error) {
	lfn := LockFileName(name)
	fm, err := filemutex.New(lfn)
	if err != nil {
		return nil, fmt.Errorf("error creating mutex file %s: %w", lfn, err)
	}

	lockChan := internalAcquire(fm)
	select {
	case <-ctx.Done():
		_ = internalRelease(fm, lfn, m.Logger)
		return nil, ctx.Err()
	case err := <-lockChan:
		if err != nil {
			_ = internalRelease(fm, lfn, m.Logger)
			return nil, fmt.Errorf("error acquiring lock on file %s: %w", lfn, err)
		}
		return &Lock{Data: fm, Name: name}, nil
	}
}

// Release release the specified lock
func (m *Mutex) Release(lock *Lock) error {
	fm := lock.Data.(*filemutex.FileMutex)
	lfn := LockFileName(lock.Name)
	return internalRelease(fm, lfn, m.Logger)
}
