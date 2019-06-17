package env

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/google/wire"
	"github.com/int128/kubelogin/adaptors"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

// Set provides an implementation and interface for Env.
var Set = wire.NewSet(
	Env{},
	wire.Bind((*adaptors.Env)(nil), (*Env)(nil)),
)

// Env provides environment specific facilities.
type Env struct{}

// ReadPassword reads a password from the stdin without echo back.
func (*Env) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, "Password: "); err != nil {
		return "", errors.Wrapf(err, "could not write the prompt")
	}
	b, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", errors.Wrapf(err, "could not read")
	}
	if _, err := fmt.Fprintln(os.Stderr); err != nil {
		return "", errors.Wrapf(err, "could not write a new line")
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
		return 0, errors.Wrapf(err, "could not execute the command")
	}
	return 0, nil
}
