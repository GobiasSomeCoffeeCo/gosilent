package silentscan

import (
	"github.com/google/gopacket/layers"
)

func handleFlags(opts *ScanOptions, tcp *layers.TCP) {
	// SYN defaults to true. If users specify flags, 
	// we'll assume they prefer it off. We'll verify at the end if they want it enabled.
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
