package main

import (
	"context"
	"os"

	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
)

var version = "HEAD"

func main() {
	cmd := adaptors.Cmd{
		Login: &usecases.Login{},
	}
	os.Exit(cmd.Run(context.Background(), os.Args, version))
}
