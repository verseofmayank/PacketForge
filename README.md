# PacketForge — Linux Network Packet Analyzer & L3 Forwarding Engine

A raw-socket packet analyzer built in C++ that captures live network traffic, parses
Ethernet, IPv4, TCP, UDP, and ARP headers, and includes a rule-based L3 forwarding
engine that filters packets by IP/port — simulating basic firewall/router logic.

## Features
- Raw socket packet capture (AF_PACKET, SOCK_RAW)
- Ethernet header parsing (src/dst MAC, EtherType)
- IPv4 header parsing (src/dst IP, protocol, TTL)
- TCP/UDP header parsing (src/dst ports)
- ARP and ICMP detection
- Rule-based L3 forwarding engine (ALLOW/DROP decisions by IP/port)
- Live packet statistics (total, allowed, dropped)

## Project Structure
PacketForge/
- src/sniffer.cpp      -> packet capture + header parsing
- src/forwarder.cpp    -> sniffer + rule-based forwarding engine
- include/headers.hpp  -> Ethernet/IP/TCP/UDP struct definitions
- include/rules.hpp    -> rule table + Action enum

## Build

Sniffer only:
g++ src/sniffer.cpp -o sniffer

Forwarding engine:
g++ src/forwarder.cpp -o forwarder

## Run
Requires root (raw sockets need CAP_NET_RAW):

sudo ./sniffer
sudo ./forwarder

## Example Output — Sniffer
--- Packet (98 bytes) ---
Src MAC: 00:15:5d:6e:42:c7
Dst MAC: 00:15:5d:6e:47:2f
EtherType: 0x0800
Src IP: 192.168.1.10
Dst IP: 142.250.193.14
Protocol: 6 (TCP)
Src Port: 52341
Dst Port: 443

## Forwarding Engine
forwarder.cpp inspects each packet's source/destination IP and port, checks it
against a configurable rule table, and decides ALLOW or DROP.

Rule table example:
- any -> any : port 22  -> DROP (block SSH)
- any -> any : port 445 -> DROP (block SMB)
- any -> any : default  -> ALLOW

Example output:
Src: 127.0.0.1 -> Dst: 127.0.0.1:22 | Protocol: 6 | Decision: DROP
Src: 172.31.13.131 -> Dst: 192.178.134.138:80 | Protocol: 6 | Decision: ALLOW

[Stats] Total: 20 | Allowed: 18 | Dropped: 2

## Roadmap (V3)
- IPv6 support
- Multithreaded packet capture
- Real packet retransmission (actual forwarding, not just decision logging)
- DHCP/ARP-based dynamic rule updates

## Tech Stack
C++, POSIX raw sockets, Linux networking stack

## Author
Mayank Kumar Karn
