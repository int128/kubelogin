package di_test

import (
	"testing"

	adaptors "github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/di"
)

func TestInvoke(t *testing.T) {
	if err := di.Invoke(func(cmd adaptors.Cmd) {
		if cmd == nil {
			t.Errorf("cmd wants non-nil but nil")
		}
	}); err != nil {
		t.Fatalf("Invoke returned error: %+v", err)
	}
}
