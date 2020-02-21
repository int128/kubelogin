// Package reader provides the reader of standard input.
package reader

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/google/wire"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_reader/mock_reader.go github.com/int128/kubelogin/pkg/adaptors/reader Interface

// Set provides an implementation and interface for Reader.
var Set = wire.NewSet(
	wire.Struct(new(Reader), "*"),
	wire.Bind(new(Interface), new(*Reader)),
)

type Interface interface {
	ReadString(prompt string) (string, error)
	ReadPassword(prompt string) (string, error)
}

type Reader struct{}

// ReadString reads a string from the stdin.
func (*Reader) ReadString(prompt string) (string, error) {
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
func (*Reader) ReadPassword(prompt string) (string, error) {
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
