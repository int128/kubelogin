package adaptors

import (
	"context"
)

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}

// LogLevel represents a log level for debug.
//
// 0 = None
// 1 = Including in/out
// 2 = Including transport headers
// 3 = Including transport body
//
type LogLevel int
