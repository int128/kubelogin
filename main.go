package main

import (
	"log"
	"os"

	"github.com/int128/kubelogin/cli"
)

func main() {
	c, err := cli.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Run(); err != nil {
		log.Fatal(err)
	}
}
