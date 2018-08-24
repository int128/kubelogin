package main

import (
	"context"
	"log"
	"os"

	"github.com/int128/kubelogin/cli"
)

func main() {
	c, err := cli.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
