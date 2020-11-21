package mutex

import (
	"fmt"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"golang.org/x/net/context"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestMutex(t *testing.T) {

	t.Run("Test successful parallel acquisition with no reentry allowed", func(t *testing.T) {

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		nbConcurrency := 20
		wg := sync.WaitGroup{}
		events := make(chan int, nbConcurrency*2)
		errors := make(chan error, nbConcurrency)
		doLockUnlock := func() {
			defer wg.Done()

			m := Mutex{
				Logger: logger.New(),
			}
			if mutex, err := m.Acquire(ctx, "test"); err == nil {
				events <- 1
				var dur = time.Duration(rand.Intn(5000))
				time.Sleep(dur * time.Microsecond)
				events <- -1
				if err := m.Release(mutex); err != nil {
					errors <- fmt.Errorf("Release error: %w", err)
				}
			} else {
				errors <- fmt.Errorf("Acquire error: %w", err)
			}
		}

		for i := 0; i < nbConcurrency; i++ {
			wg.Add(1)
			go doLockUnlock()
		}

		wg.Wait()
		close(events)
		close(errors)

		countConcurrent := 0
		for delta := range events {
			countConcurrent += delta
			if countConcurrent > 1 {
				t.Errorf("The mutex did not prevented reentry: %d", countConcurrent)
			}
		}

		for anError := range errors {
			t.Errorf("The gorouting returned an error: %s", anError)
		}
	})
}
