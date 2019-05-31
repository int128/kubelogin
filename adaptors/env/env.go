package env

import (
	"fmt"
	"os"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

// Env provides environment specific facilities.
type Env struct{}

// ReadPassword reads a password from the stdin without echo back.
func (*Env) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, "Password: "); err != nil {
		return "", errors.Wrapf(err, "could not write the prompt")
	}
	b, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return "", errors.Wrapf(err, "could not read")
	}
	if _, err := fmt.Fprintln(os.Stderr); err != nil {
		return "", errors.Wrapf(err, "could not write a new line")
	}
	return string(b), nil
}
