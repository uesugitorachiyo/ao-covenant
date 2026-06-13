package main

import (
	"os"

	"github.com/uesugitorachiyo/ao-covenant/internal/cli"
)

func main() {
	os.Exit(cli.RunWithInput(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
