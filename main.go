package main

import (
	"fmt"

	"github.com/GobiasSomeCoffeeCo/gosilent/pkg/syn"
)

func main() {
	opts := ParseCLI()

	// Handle the ports
	portRange, err := GetPorts(opts.Ports)
	if err != nil {
		fmt.Printf("%v", err)
	}
	opts.PortRanges = portRange

	silentscan.SynScan(opts)

}
