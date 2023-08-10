package main

import (
	"github.com/GobiasSomeCoffeeCo/gosilent/pkg/syn"
)

func main() {
	opts := ParseCLI()

	silentscan.SynScan(opts)

}
