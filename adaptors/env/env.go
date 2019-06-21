package env

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

// Set provides an implementation and interface for Env.
var Set = wire.NewSet(
	wire.Struct(new(Env), "*"),
	wire.Bind(new(adaptors.Env), new(*Env)),
)

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

func (*Env) Exec(ctx context.Context, executable string, args []string) (int, error) {
	c := exec.CommandContext(ctx, executable, args...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return err.ExitCode(), nil
		}
		return 0, xerrors.Errorf("could not execute the command: %w", err)
	}
	return 0, nil
}
