package main

import (
	"os"

	"github.com/RarimoVoting/identity-provider-service/internal/cli"
)

func main() {
	if !cli.Run(os.Args) {
		os.Exit(1)
	}
}
