package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handleMap map[string]*pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func newScanner(ip net.IP, router routing.Router) (*scanner, error) {
	s := &scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	// Figure out the route to the IP.
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	log.Printf("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	// Open the handle for reading/writing.
	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	s.handleMap = make(map[string]*pcap.Handle)

	s.getHandle(iface.Name)
	return s, nil
}

// close cleans up the handle.

func (s *scanner) getHandle(ifaceName string) (*pcap.Handle, error) {
	if handle, ok := s.handleMap[ifaceName]; ok {
		return handle, nil
	} else {
		handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
		if err != nil {
			return nil, err
		}
		s.handleMap[ifaceName] = handle
		return handle, nil
	}
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.

func (s *scanner) getHwAddr(arpDst net.IP, resultChan chan<- net.HardwareAddr) {
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst.To4()),
	}
	// Send a single ARP request packet.
	if err := s.send(&eth, &arp); err != nil {
		// Handle error.
		log.Printf("Unable to send arp request packet: %v", err)
	}
	log.Println("Getting HW address")
	go func() {
		for {
			handle, ok := s.handleMap[s.iface.Name]
			if !ok {
				log.Println("Unable to get PCAP handle")
			}

			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				log.Println("NextErrorTimeoutExpired")
				continue
			} else if err != nil {
				log.Println("Error in handling ReadPacketData()")
			}
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				if net.IP(arp.SourceProtAddress).Equal(arpDst) {
					resultChan <- net.HardwareAddr(arp.SourceHwAddress)
					return
				}
			}
		}
	}()
}

// close cleans up the handle.
func (s *scanner) close() {
	handle, ok := s.handleMap[s.iface.Name]
	if !ok {
		log.Println("Unable to get PCAP handle")
	}
	handle.Close()
}

// scan scans the dst IP address of this scanner.
func (s *scanner) scan() error {
	// First off, get the MAC address we should be sending packets to.
	hwaddrChan := make(chan net.HardwareAddr)
	defer close(hwaddrChan)

	// First off, get the MAC address we should be sending packets to.
	for _, arpDst := range flag.Args() {
		ip := net.ParseIP(arpDst)
		if ip == nil {
			continue
		}
		//		go s.getHwAddr(ip, hwaddrChan)
	}

	//hwaddr, ok := <-hwaddrChan

	//if !ok || hwaddr == nil {
	// Handle error.
	//log.Println("Unable to get hwaddrChan")
	//}
	// Construct all the network layers we need.
	// Manually added DstMac hardware address as it was holding up the program when running getHwAddr
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xf0, 0x81, 0x75, 0x03, 0x50, 0x92},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Id:       23757,
		Version:  4,
		TTL:      42,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 21, // will be incremented during the scan
		SYN:     true,
		Window:  1024,
		Seq:     35476,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xb4}},
		},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	handle := s.handleMap[s.iface.Name]
	// Create channels for communication between goroutines
	done := make(chan bool)
	packetCh := make(chan gopacket.Packet)

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)

	// Goroutine for sending packets
	go func() {
		defer close(done) // Notify other goroutine when done

		start := time.Now()
		fmt.Println("Starting Syn Scan...")

		for tcp.DstPort < 65535 {
			start = time.Now()

			port := randomizer()
			id := randomizer()
			ip4.Id = uint16(id)

			tcp.DstPort++
			tcp.SrcPort = layers.TCPPort(port)
			if err := s.send(&eth, &ip4, &tcp); err != nil {
				log.Printf("error sending to port %v: %v", tcp.DstPort, err)
			}
		}

		// Timeout if no packets sent for 5 seconds
		if time.Since(start) > time.Second*5 {
			log.Printf("timed out for %v, assuming we've seen all we can", s.dst)
		}
	}()

	// Goroutine for receiving and processing packets
	go func() {
		for {
			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			} else if err != nil {
				log.Printf("error reading packet: %v", err)
				continue
			}

			// Create packet and send to channel
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			packetCh <- packet
		}
	}()

	// Process packets from the channel
	for {
		select {
		case packet, ok := <-packetCh:
			if !ok {
				return nil // Exit if channel closed
			}

			if net := packet.NetworkLayer(); net == nil {
				//log.Printf("packet has no network layer") //
			} else if net.NetworkFlow() != ipFlow {
				//log.Printf("packet does not match our ip src/dst") //
			} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
				//log.Printf("packet has not tcp layer") //
			} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
				// We panic here because this is guaranteed to never
				// happen.
				panic("tcp layer is not tcp layer :-/")
				//} else if tcp.DstPort != 54321 {
				//log.Printf("dst port %v does not match", tcp.DstPort) //
			} else if tcp.RST {
				//log.Printf("  port %v closed", tcp.SrcPort)
			} else if tcp.SYN && tcp.ACK {
				log.Printf("%s %v open", GOOD, tcp.SrcPort)
			} else {
				log.Printf("ignoring useless packet") //
			}

		case <-done:
			return nil // Exit if done sending packets
		}
	}

}

// send sends the given layers as a single packet on the network.
func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}

	handle, ok := s.handleMap[s.iface.Name]
	if !ok {
		log.Println("Unable to access PCAP handle")
	}
	return handle.WritePacketData(s.buf.Bytes())
}

func randomizer() int {
	rand.Seed(time.Now().UnixNano())
	min := 49152
	max := 65535
	port := rand.Intn(max-min+1) + min

	return port
}

func main() {
	defer util.Run()()
	router, err := routing.New()
	if err != nil {
		log.Fatal("routing error:", err)
	}

	var wg sync.WaitGroup // Add a wait group to wait for all goroutines

	for _, arg := range flag.Args() {
		var ip net.IP
		if ip = net.ParseIP(arg); ip == nil {
			log.Printf("non-ip target: %q", arg)
			continue
		} else if ip = ip.To4(); ip == nil {
			log.Printf("non-ipv4 target: %q", arg)
			continue
		}

		wg.Add(1) // Increment wait group counter

		// This goroutine is unnecessary at the moment, but will allow for passing multiple IP's to be scanned
		go func(ip net.IP) { // Launch a goroutine for each IP to scan
			defer wg.Done() // Decrement wait group counter when goroutine completes

			s, err := newScanner(ip, router)
			log.Println(".....")
			if err != nil {
				log.Printf("unable to create scanner for %v: %v", ip, err)
				return
			}
			log.Println("About to scan...")
			if err := s.scan(); err != nil {
				log.Printf("unable to scan %v: %v", ip, err)
			}
			s.close()
		}(ip)
	}

	wg.Wait()
}