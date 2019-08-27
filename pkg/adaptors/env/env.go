package env

import (
	"fmt"
	"os"
	"syscall"

	"github.com/google/wire"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_env/mock_env.go github.com/int128/kubelogin/pkg/adaptors/env Interface

// Set provides an implementation and interface for Env.
var Set = wire.NewSet(
	wire.Struct(new(Env), "*"),
	wire.Bind(new(Interface), new(*Env)),
)

type Interface interface {
	ReadPassword(prompt string) (string, error)
}

// Env provides environment specific facilities.
type Env struct{}

// ReadPassword reads a password from the stdin without echo back.
func (*Env) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, "Password: "); err != nil {
		return "", xerrors.Errorf("could not write the prompt: %w", err)
	}
	b, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", xerrors.Errorf("could not read: %w", err)
	}
	if _, err := fmt.Fprintln(os.Stderr); err != nil {
		return "", xerrors.Errorf("could not write a new line: %w", err)
	}
	return string(b), nil
}
