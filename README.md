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

# Running GoSilent against your target IP

# Ensure you run the binary with root privileges:
sudo ./gosilent -t <target IP address>
# Example:
sudo ./gosilent -t 192.168.1.1
```

**Enhanced Scanning with Interface and Network Flags:**

You now have the flexibility to use interface and network flags with GoSilent to customize your scans.

**Interface Flags:**

    -i <Network interface> If empty, it will fallback to system defaults.

Example:

```bash
sudo ./gosilent -t 192.168.1.1 -i eno2
```
**Network Flags:**

    -sF Set FIN flag for TCP
    -sS Set SYN flag for TCP
    -sA Set ACK flag for TCP
    -sU Set URG flag for TCP
    -sP Set PSH flag for TCP
    -sR Set RST flag for TCP
    -sX Set 'XMas Flag' (URG PSH FIN) for TCP

Example:

```bash
sudo ./gosilent -t 192.168.1.1 -sF -sA -sP
```

Feel free to mix and match flags as per your requirements!

**Utility Flags:**

    -b Enable a service banner grabber. A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within two seconds. 
    -v Enable verbose mode for real-time display of newly opened ports.

Example:

```bash
sudo ./gosilent -t 192.168.1.1 -b -v
```