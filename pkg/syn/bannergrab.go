package silentscan

import (
	"fmt"
	"log"
	"net"
	"time"

	//"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func BannerGrab(s *ScanResults) {
	conn, err := net.Dial("tcp", s.TargetIP+":"+s.Port)
	if err != nil {
		log.Fatalf("Failed to connect: %s", err)
	}
	defer conn.Close()

	handle, err := pcap.OpenLive(s.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open live capture: %s", err)
	}
	defer handle.Close()

	go func() {
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		s.Banner = fmt.Sprintf("Banner: %s\n", buf[:n])
	}()

}
