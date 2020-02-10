package browser

import (
	"os"

	"github.com/google/wire"
	"github.com/pkg/browser"
)

//go:generate mockgen -destination mock_browser/mock_browser.go github.com/int128/kubelogin/pkg/adaptors/browser Interface

func init() {
	// In credential plugin mode, some browser launcher writes a message to stdout
	// and it may break the credential json for client-go.
	// This prevents the browser launcher from breaking the credential json.
	browser.Stdout = os.Stderr
}

// Set provides an implementation and interface for Env.
var Set = wire.NewSet(
	wire.Struct(new(Browser)),
	wire.Bind(new(Interface), new(*Browser)),
)

type Interface interface {
	Open(url string) error
}

type Browser struct{}

// Open opens the default browser.
func (*Browser) Open(url string) error {
	return browser.OpenURL(url)
}
