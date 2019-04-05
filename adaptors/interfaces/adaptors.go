package adaptors

import "context"

type Cmd interface {
	Run(ctx context.Context, args []string, version string) int
}
