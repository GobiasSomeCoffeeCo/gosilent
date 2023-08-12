package silentscan

import (
	"github.com/google/gopacket/layers"
)

func handleFlags(opts *ScanOptions, tcp *layers.TCP) {
	// Since SYN is by default set to true, if users start utilizing flags we'll
	// assume they dont want it automatically turned on. We'll set it to off 
	// and check at the end if they still want it on
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
