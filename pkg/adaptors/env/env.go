// Package env provides environment dependent facilities.
package env

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

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
	ReadString(prompt string) (string, error)
	ReadPassword(prompt string) (string, error)
	Now() time.Time
}

// Env provides environment specific facilities.
type Env struct{}

// ReadString reads a string from the stdin.
func (*Env) ReadString(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", xerrors.Errorf("could not write the prompt: %w", err)
	}
	r := bufio.NewReader(os.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		return "", xerrors.Errorf("could not read from stdin: %w", err)
	}
	s = strings.TrimRight(s, "\r\n")
	return s, nil
}

// ReadPassword reads a password from the stdin without echo back.
func (*Env) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", xerrors.Errorf("could not write the prompt: %w", err)
	}
	b, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", xerrors.Errorf("could not read from stdin: %w", err)
	}
	if _, err := fmt.Fprintln(os.Stderr); err != nil {
		return "", xerrors.Errorf("could not write a new line: %w", err)
	}
	return string(b), nil
}

// Now returns the current time.
func (*Env) Now() time.Time {
	return time.Now()
}
