package adaptors

import (
	"context"
	"testing"

	"github.com/int128/kubelogin/usecases/interfaces"
)

//TODO: Use gomock
type mockLogin struct{}

func (*mockLogin) Do(ctx context.Context, in usecases.LoginIn) error {
	return nil
}

func TestCmd_Run(t *testing.T) {
	cmd := Cmd{
		Login: &mockLogin{},
	}

	t.Run("NoArg", func(t *testing.T) {
		exitCode := cmd.Run(context.TODO(), []string{"kubelogin"}, "version")
		if exitCode != 0 {
			t.Errorf("exitCode wants 0 but %d", exitCode)
		}
	})

	t.Run("TooManyArgs", func(t *testing.T) {
		exitCode := cmd.Run(context.TODO(), []string{"kubelogin", "some"}, "version")
		if exitCode != 1 {
			t.Errorf("exitCode wants 1 but %d", exitCode)
		}
	})
}
