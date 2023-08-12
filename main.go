package main

import (
	"fmt"

	"github.com/GobiasSomeCoffeeCo/gosilent/pkg/syn"
)

func main() {
	opts := ParseCLI()

	silentscan.SynScan(opts)
	fmt.Println("\033[1;94mAll Done!!!\033[0m")
}
