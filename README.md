# gosilent
A silent SYN scanner. 

This is an updated take on the [Gopacket Synscan](https://github.com/google/gopacket/blob/master/examples/synscan/main.go). It used to take several minutes for a scan to complete. It now can can run through all 65535 ports in a matter of seconds.

If you want to try it out, seel below...

You'll need libpcap installed on your system for this program to work. The installation of libpcap depends on your operating system:

    * On Ubuntu, you can install it using the command: sudo apt-get install libpcap-dev
    * On macOS, you can install it using the command: brew install libpcap
    * On Windows, it's more complex. Windows doesn't natively support libpcap, but you can use the Npcap or WinPcap libraries, which provide similar functionality.

    * Make sure you have go downloaded.

```bash
git clone https://github.com/GobiasSomeCoffeeCo/gosilent.git
```

```bash
cd gosilent
```

```bash
go build
```

```bash
./gosilent <target IP address>
./gosilent 192.168.1.1
```

