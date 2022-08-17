// Package reader provides the reader of standard input.
package reader

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/google/wire"
	"github.com/int128/kubelogin/pkg/infrastructure/stdio"
	"golang.org/x/term"
)

// Set provides an implementation and interface for Reader.
var Set = wire.NewSet(
	wire.Struct(new(Reader), "*"),
	wire.Bind(new(Interface), new(*Reader)),
)

type Interface interface {
	ReadString(prompt string) (string, error)
	ReadPassword(prompt string) (string, error)
}

type Reader struct {
	Stdin stdio.Stdin
}

// ReadString reads a string from the stdin.
func (x *Reader) ReadString(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", fmt.Errorf("write error: %w", err)
	}
	r := bufio.NewReader(x.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}
	s = strings.TrimRight(s, "\r\n")
	return s, nil
}

// ReadPassword reads a password from the stdin without echo back.
func (*Reader) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", fmt.Errorf("write error: %w", err)
	}
	b, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}
	if _, err := fmt.Fprintln(os.Stderr); err != nil {
		return "", fmt.Errorf("write error: %w", err)
	}
	return string(b), nil
}
