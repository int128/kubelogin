// Package clock provides the system clock.
package clock

import (
	"time"

	"github.com/google/wire"
)

var Set = wire.NewSet(
	wire.Struct(new(Clock), "*"),
	wire.Bind(new(Interface), new(*Clock)),
)

type Interface interface {
	Now() time.Time
}

type Clock struct{}

// Now returns the current time.
func (c *Clock) Now() time.Time {
	return time.Now()
}
