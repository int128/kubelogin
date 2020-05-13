// Package clock provides the system clock.
package clock

import (
	"time"

	"github.com/google/wire"
)

var Set = wire.NewSet(
	wire.Struct(new(Real), "*"),
	wire.Bind(new(Interface), new(*Real)),
)

type Interface interface {
	Now() time.Time
}

type Real struct{}

// Now returns the current time.
func (c *Real) Now() time.Time {
	return time.Now()
}
