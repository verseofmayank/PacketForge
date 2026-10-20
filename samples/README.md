# Synthetic PacketForge captures

Every capture was generated locally by `python3 scripts/generate_fixtures.py` using
only the Python standard library. The script writes files and never sends packets.
Source ranges are RFC 5737 documentation IPv4 ranges and `2001:db8::/32` for IPv6;
MAC addresses are synthetic locally administered values. There are no real users,
credentials, third-party captures or runtime packet-building dependencies.

Timestamps begin at 2023-11-14T22:13:20Z. Files use classic Ethernet PCAP, mostly
little-endian with microsecond timestamp resolution. Protocol checksums are
constructed for normal IP/TCP/ICMP messages; zero IPv4 UDP checksums are legal.
The normal TCP example shows SYN, SYN/ACK, ACK and FIN/ACK metadata, without claiming
a complete session or application exchange. DNS contains a harmless `example.test`
query; PacketForge treats it as UDP metadata, not decoded DNS.

| Fixture | Packets | Default alerts / expected behavior |
| --- | ---: | --- |
| `normal_tcp.pcap` | 4 | None; 2 directional flows |
| `normal_udp_dns.pcap` | 2 | None; UDP including one port-53 query |
| `arp.pcap` | 1 | None; Ethernet/IPv4 ARP request |
| `icmp.pcap` | 2 | None; echo request and reply |
| `ipv6.pcap` | 1 | None; ICMPv6 echo request |
| `demo.pcap` | 9 | None; benign mixed traffic |
| `portscan.pcap` | 13 | One POSSIBLE_TCP_PORT_SCAN, observed count 12 |
| `synrate.pcap` | 101 | One HIGH_TCP_SYN_RATE, observed count 100; repeated same attempt |
| `icmp_rate.pcap` | 51 | One HIGH_ICMP_ECHO_RATE, observed count 50 |
| `concentration.pcap` | 41 | One CONNECTION_CONCENTRATION, observed count 40 |
| `sensitive.pcap` | 1 | One INFO SENSITIVE_SERVICE_TRAFFIC; policy WOULD_BLOCK for port 22 |
| `malformed.pcap` | 2 | No alerts; 1 truncated capture, 1 invalid IPv4 IHL |
| `mixed.pcap` | 21 | One POSSIBLE_TCP_PORT_SCAN; ARP, IPv4, IPv6, TCP, UDP, ICMP |
| `nanosecond.pcap` | 1 | Timestamp ends `.123456789Z` |
| `big_endian.pcap` | 1 | Valid alternate-byte-order PCAP |
| `empty.pcap` | 0 | Valid empty capture; rates null/not applicable |
| `out_of_order.pcap` | 2 | Error: nonchronological timestamps; no successful report |
| `unsupported_link.pcap` | 1 | Error: non-Ethernet link type |

`expected.json` is consumed by integration tests for ordinary analyses. The special
byte-order, timestamp and error fixtures are asserted separately. Integration tests
also construct a short/corrupt file and PCAPNG magic in a temporary directory.

```bash
python3 scripts/generate_fixtures.py
./build/packetforge analyze --pcap samples/mixed.pcap --report all
```

Randomized and crafted unit tests cover additional VLAN, options, extension-header,
fragmentation and invalid-length cases directly, rather than requiring a PCAP file
for every byte-level mutation.
