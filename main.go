package main

import (
	"fmt"
	"strings"

	"github.com/GobiasSomeCoffeeCo/gosilent/pkg/display"
	"github.com/GobiasSomeCoffeeCo/gosilent/pkg/syn"
)

func main() {
	resultsChannel := make(chan *silentscan.ScanResults)
	opts := ParseCLI()

	go silentscan.SynScan(opts, resultsChannel)

	var res []*silentscan.ScanResults

	for data := range resultsChannel {
		res = append(res, data)
	}

	if opts.Banner {
		fmt.Printf("%s Scan Complete. Attempting to Grab Banners...\n", display.INFO)
		fmt.Println(display.LINE)
	}

	for _, v := range res {
		if opts.Banner {
			silentscan.GetTCPBanner(v)
			if v.Port == "80" || v.Port == "443" || v.Port == "8000" || v.Port == "8008" || v.Port == "8080" || v.Port == "8443" || v.Port == "8888" {
				_, err := silentscan.GetHTTPBanner(v)
				if err != nil {
					fmt.Println(err)
				}
			}
		}
		if len(v.Banner) == 9 || v.Banner == "" {
			fmt.Printf("%v\n", v.Status)
			continue
		} else {
			fmt.Printf("%v %v\n", v.Status, strings.TrimSpace(v.Banner))
		}
	}

	fmt.Println(display.LINE)
	fmt.Printf("%s All Done!!!\n", display.RES)
}
