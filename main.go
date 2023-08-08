package main

import (
	"github.com/GobiasSomeCoffeeCo/gosilent/pkg/syn"
)

func main() {
	opts := ParseCLI()

	// Handle the ports

	silentscan.SynScan(opts)

}
