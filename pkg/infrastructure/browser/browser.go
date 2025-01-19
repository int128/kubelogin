package browser

import (
	"context"
	"os"
	"os/exec"

	"github.com/google/wire"
	"github.com/pkg/browser"
)

func init() {
	// In credential plugin mode, some browser launcher writes a message to stdout
	// and it may break the credential json for client-go.
	// This prevents the browser launcher from breaking the credential json.
	browser.Stdout = os.Stderr
}

var Set = wire.NewSet(
	wire.Struct(new(Browser)),
	wire.Bind(new(Interface), new(*Browser)),
)

type Interface interface {
	Open(url string) error
	OpenCommand(ctx context.Context, url, command string) error
}

type Browser struct{}

// Open opens the default browser.
func (*Browser) Open(url string) error {
	return browser.OpenURL(url)
}

// OpenCommand opens the browser using the command.
func (*Browser) OpenCommand(ctx context.Context, url, command string) error {
	c := exec.CommandContext(ctx, command, url)
	c.Stdout = os.Stderr // see above
	c.Stderr = os.Stderr
	return c.Run()
}
