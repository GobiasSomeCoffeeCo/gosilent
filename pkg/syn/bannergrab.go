package silentscan

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

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

func GetHTTPBanner(s *ScanResults) (string, error) {
	s.TargetIP = "http://" + s.TargetIP
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Head(s.TargetIP)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		return "No Server header found", nil
	}
	s.Banner = fmt.Sprintf("Banner: %s\n", serverHeader)
	return serverHeader, nil
}
