// Package stdio wraps os.Stdin and os.Stdout for testing.
package stdio

import (
	"io"
	"os"

	"github.com/google/wire"
)

var Set = wire.NewSet(
	wire.InterfaceValue(new(Stdin), os.Stdin),
	wire.InterfaceValue(new(Stdout), os.Stdout),
)

type Stdout io.Writer
type Stdin io.Reader
