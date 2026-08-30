package main

import (
	"context"
	_ "embed"
	"os"
	"os/signal"
	"syscall"

	"github.com/int128/kubelogin/pkg/di"
)

//go:embed VERSION
var version string

func main() {
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(di.NewCmd().Run(ctx, os.Args, version))
}
