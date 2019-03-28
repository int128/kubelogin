package main

import (
	"context"
	"github.com/int128/kubelogin/adaptors"
	"github.com/int128/kubelogin/usecases"
	"os"
)

//TODO: inject version

func main() {
	cmd := adaptors.Cmd{
		Login: &usecases.Login{},
	}
	os.Exit(cmd.Run(context.Background(), os.Args))
}
