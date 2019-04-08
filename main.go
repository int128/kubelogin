package main

import (
	"context"
	"log"
	"os"

	"github.com/int128/kubelogin/adaptors/interfaces"
	"github.com/int128/kubelogin/di"
)

var version = "HEAD"

func main() {
	if err := di.Invoke(func(cmd adaptors.Cmd) {
		os.Exit(cmd.Run(context.Background(), os.Args, version))
	}); err != nil {
		log.Fatalf("Error: %s", err)
	}
}
