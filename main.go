package main

import (
	"os"

	"github.com/rarimo/passport-identity-provider/internal/cli"
)

func main() {
	if !cli.Run(os.Args) {
		os.Exit(1)
	}
}
