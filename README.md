# GoSilent: The Speedy Silent SYN Scanner

Introducing GoSilent - an enhanced and accelerated version of the [Gopacket Synscan](https://github.com/google/gopacket/blob/master/examples/synscan/main.go). While the traditional scan could take minutes, GoSilent breezes through all 65535 ports in mere seconds.

**Ready to give it a whirl? Here's how:**

Before you begin, ensure `libpcap` is installed on your system:

- **Ubuntu**: Install using `sudo apt-get install libpcap-dev`
- **macOS**: Install with `brew install libpcap`
- **Windows**: A tad trickier. Native support for libpcap is absent, but Npcap or WinPcap libraries serve as suitable alternatives.

And don't forget, you should have Go set up on your machine.

**Getting Started with GoSilent:**

```bash
# Clone the repository
git clone https://github.com/GobiasSomeCoffeeCo/gosilent.git

# Navigate to the directory
cd gosilent

# Build the application
go build

# Run GoSilent against your target IP
./gosilent <target IP address>
# Example:
./gosilent 192.168.1.1
```

