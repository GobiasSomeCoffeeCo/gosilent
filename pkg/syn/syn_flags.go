package silentscan

import (
	"github.com/google/gopacket/layers"
)

func handleFlags(opts *ScanOptions, tcp *layers.TCP) *layers.TCP {
	if opts.UseACK == true {
		tcp.ACK = true
	}
	if opts.UseFIN == true {
		tcp.FIN = true
	}
	if opts.UseRST == true {
		tcp.RST = true
	}
	if opts.UseNS == true {
		tcp.NS = true
	}
	if opts.UsePSH == true {
		tcp.PSH = true
	}
	if opts.UseURG == true {
		tcp.URG = true
	}
	if opts.UseXMas == true {
		tcp.FIN = true
		tcp.PSH = true
		tcp.URG = true
	}
	return tcp
}
