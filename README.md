# tcpdump for Windows

This is a `tcpdump`-like tool specifically designed for Windows, written in Go. It leverages `gopacket` and `pcap` libraries to capture, filter, and analyze network packets on your system.

I wanted to use tcpdump on Windows computers, but the previous software I used by MicroOlap hasn't been updated and blue screens newer versions of Windows workstations on execution. My goal with this project was to be able to use tcpdump syntax to do a packet capture on a computer in a single executable.

## Features

*   **Packet Capture:** Capture live network traffic from a selected interface.
*   **Interface Listing:** Easily list all available network interfaces on your system.
*   **BPF Filtering:** Apply Berkeley Packet Filter (BPF) syntax to filter packets of interest.
*   **PCAP Input:** Read packets from a `.pcap` file for offline analysis.
*   **PCAP Output:** Save raw captured packets to a `.pcap` file for later analysis with tools like Wireshark.
*   **Verbose Output:** Display detailed packet information, including IP, TCP, UDP, ICMP, and HTTP specifics.
*   **Protocol Decoding:** Basic decoding for HTTP, DNS (UDP), and ICMP protocols.
*   **Npcap Integration:** Automatically checks for and attempts to install Npcap, which is required for packet capture on Windows.

## Usage

Open Command Prompt or PowerShell to run these commands.

### List Interfaces

To see a list of available network interfaces:

```
tcpdump.exe -D
```

### Capture Packets

To capture packets on a specific interface (e.g., interface number 1):

```
tcpdump.exe -i 1
```

Or by interface name:

```
tcpdump.exe -i "Ethernet"
```

If the interface name contains spaces, it's a good practice to enclose it in quotes.

### Verbose Output

For more detailed packet information:

```
tcpdump.exe -i 1 -v
```

### Read from PCAP File

To read packets from a saved `.pcap` file (e.g., `capture.pcap`):

```
tcpdump.exe -r capture.pcap
```

You can also combine it with verbose output:

```
tcpdump.exe -r capture.pcap -v
```

### Write to PCAP File

To capture packets and save them to a `.pcap` file (e.g., `capture.pcap`):

```
tcpdump.exe -i 1 -w capture.pcap
```

### Filtering

You can apply BPF filters to capture only specific traffic. For example, to capture only HTTP traffic (port 80 and 443):

```
tcpdump.exe -i 1 "port 80 or port 443"
```

To capture traffic from a specific host:

```
tcpdump.exe -i 1 "host 192.168.1.1"
```

## Requirements

*   Windows Operating System
*   Npcap (The tool will attempt to install it if not found)

## Build from Source (if applicable)

If you have the Go toolchain installed, you can build this project from source:

```
git clone https://github.com/mattros-gh/tcpdump-windows.git
cd tcpdump-windows
go build -o tcpdump.exe .
```

---
tcpdump for Windows written by Matt Roszel
matt@b-compservices.com
