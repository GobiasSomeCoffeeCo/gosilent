package silentscan

import (
	"github.com/google/gopacket/layers"
)

func handleFlags(opts *ScanOptions, tcp *layers.TCP) {
	// Since SYN is always set to true, if users start utilizing flags we'll
	// turn it off and check at the end if they still want it turned on
	if opts.UseACK {
		tcp.ACK = true
		tcp.SYN = false
	}
	if opts.UseFIN {
		tcp.FIN = true
		tcp.SYN = false
	}
	if opts.UseRST {
		tcp.RST = true
		tcp.SYN = false
	}
	if opts.UseNS {
		tcp.NS = true
		tcp.SYN = false
	}
	if opts.UsePSH {
		tcp.PSH = true
		tcp.SYN = false
	}
	if opts.UseURG {
		tcp.URG = true
		tcp.SYN = false
	}
	if opts.UseXMas {
		tcp.FIN = true
		tcp.PSH = true
		tcp.URG = true
		tcp.SYN = false
	}
	if opts.UseSYN {
		tcp.SYN = true
	}
}
