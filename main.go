package main

import (
	"context"
	"os"

	"github.com/int128/kubelogin/adaptors/logger"
	"github.com/int128/kubelogin/di"
)

var version = "HEAD"

func main() {
	os.Exit(di.NewCmd(logger.NewLogger()).Run(context.Background(), os.Args, version))
}
