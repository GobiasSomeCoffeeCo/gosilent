package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/GobiasSomeCoffeeCo/gosilent/pkg/syn"
)



func ParseCLI() *silentscan.ScanOptions {
	options := silentscan.ScanOptions{}

	flag.BoolVar(&options.UseFIN, "fin", false, "Set FIN flag for TCP")
	flag.BoolVar(&options.UseSYN, "syn", false, "Set SYN flag for TCP")
	flag.BoolVar(&options.UseRST, "rst", false, "Set RST flag for TCP")
	flag.BoolVar(&options.UsePSH, "psh", false, "Set PSH flag for TCP")
	flag.BoolVar(&options.UseACK, "ack", false, "Set ACK flag for TCP")
	flag.BoolVar(&options.UseURG, "urg", false, "Set URG flag for TCP")
	flag.BoolVar(&options.UseECE, "ece", false, "Set ECE flag for TCP")
	flag.BoolVar(&options.UseCWR, "cwr", false, "Set CWR flag for TCP")
	flag.BoolVar(&options.UseNS, "ns", false, "Set NS flag for TCP")
	flag.StringVar(&options.InterfaceName, "i", "", "Network interface to use")
	flag.StringVar(&options.Ports, "ports", "22,80,135,139,400-10000", "Ports to scan (e.g., 22,80,139,400-500). Use commas and hyphens for ranges.")
	flag.StringVar(&options.Target, "t", "", "The target IP you'd like to scan (e.g., 192.168.1.1)")

	flag.Parse()

	if options.Target == "" {
		fmt.Println("You must provide a target IP")
		flag.Usage()
		os.Exit(1)
	}

	return &options
}

func GetPorts(userInput string) ([]int, error) {
	userPorts := []int{}
	portRanges := strings.Split(userInput, ",")
	for _, r := range portRanges {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "-") {
			return nil, fmt.Errorf("port number cannot be negative: '%s'", r)
		}
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port selection: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[0])
			}
			if p1 < 0 {
				return nil, fmt.Errorf("port number cannot be negative: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[1])
			}
			if p2 < 0 {
				return nil, fmt.Errorf("port number cannot be negative: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				userPorts = append(userPorts, i)
			}

		} else {
			if port, err := strconv.Atoi(r); err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", r)
			} else {
				userPorts = append(userPorts, port)
			}
		}
	}
	return userPorts, nil
}
