package env

import (
	"fmt"
	"os"
	"syscall"

	"github.com/google/wire"
	"github.com/pkg/browser"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

//go:generate mockgen -destination mock_env/mock_env.go github.com/int128/kubelogin/pkg/adaptors/env Interface

func init() {
	// In credential plugin mode, some browser launcher writes a message to stdout
	// and it may break the credential json for client-go.
	// This prevents the browser launcher from breaking the credential json.
	browser.Stdout = os.Stderr
}

// Set provides an implementation and interface for Env.
var Set = wire.NewSet(
	wire.Struct(new(Env), "*"),
	wire.Bind(new(Interface), new(*Env)),
)

type Interface interface {
	ReadPassword(prompt string) (string, error)
	OpenBrowser(url string) error
}

// Env provides environment specific facilities.
type Env struct{}

// ReadPassword reads a password from the stdin without echo back.
func (*Env) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
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

// OpenBrowser opens the default browser.
func (env *Env) OpenBrowser(url string) error {
	if err := browser.OpenURL(url); err != nil {
		return xerrors.Errorf("could not open the browser: %w", err)
	}
	return nil
}
