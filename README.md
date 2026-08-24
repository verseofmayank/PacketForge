# PacketForge — Linux Network Packet Analyzer

A raw-socket packet sniffer built in C++ that captures live network traffic and parses
Ethernet, IPv4, TCP, UDP, and ARP headers to extract source/destination MAC, IP,
ports, and protocol information.

## Features
- Raw socket packet capture (`AF_PACKET`, `SOCK_RAW`)
- Ethernet header parsing (src/dst MAC, EtherType)
- IPv4 header parsing (src/dst IP, protocol, TTL)
- TCP/UDP header parsing (src/dst ports)
- ARP and ICMP detection

## Build
```bash
g++ src/sniffer.cpp -o sniffer
```

## Run
Requires root (raw sockets need `CAP_NET_RAW`):
```bash
sudo ./sniffer
```

## Example Output
