# PacketForge protocol decoding

All multibyte wire fields are decoded in network byte order (most significant byte
first). Captured length is the number of bytes actually available; wire length is
the original frame length reported by the capture source. Parsing never treats
wire length as permission to access uncaptured bytes.

## Result categories

- `ok`: supported metadata was decoded, or a deliberately skipped non-initial
  fragment/no-next-header packet was safely classified.
- `truncated`: the available capture ends before a required declared header/body.
- `malformed`: contradictory protocol lengths/fields, including IP lengths beyond
  reported wire size, invalid offsets or invalid capture/wire length combinations.
- `unsupported`: valid-looking content outside implemented formats, such as LLC,
  unknown EtherTypes/IP protocols, ESP or excessive extension depth.

The separate `capture_truncated` flag records `caplen < wirelen`, even when all
metadata lies inside the capture and only padding/payload is missing. Statistics
count capture truncation independently of the primary parse result. A packet may
therefore contribute to both a truncation counter and a malformed counter.

## Ethernet and VLAN

Ethernet II requires 14 bytes: destination MAC (6), source MAC (6), EtherType (2).
Both MACs are formatted in canonical hexadecimal. EtherTypes 0x8100 and 0x88a8
advance through a four-byte tag containing TCI and the next EtherType. The low
12 TCI bits become the VLAN ID. Two tags are supported; a third is explicitly
unsupported. IEEE 802.3 length/LLC frames are not decoded. FCS is not validated.

Live NIC VLAN offload may remove a tag from received bytes. When Linux supplies
valid `PACKET_AUXDATA` VLAN metadata, the capture adapter restores that tag before
shared parsing, updating both observed and wire lengths. Other offload effects
are not normalized.

## ARP

The initial eight bytes declare hardware/protocol types, address lengths and
opcode. The decoder checks the full variable-size layout before reading addresses.
Ethernet/IPv4 ARP (hardware type 1, protocol 0x0800, lengths 6 and 4) supports
sender/target hardware and protocol addresses plus opcode. Other address formats
are explicitly unsupported. ARP source/destination statistics use protocol addresses.
ARP spoofing detection is not implemented.

## IPv4

The decoder requires version 4 and IHL >= 5 words. It validates the complete
variable-length header, total length >= IHL, and the packet boundary against both
wire and captured lengths. It extracts version, IHL, total length, TTL, protocol,
source/destination, identification, DF/MF and fragment offset in **bytes**.
Options are bounded and skipped, not interpreted.

Reserved fragmentation flags and contradictory DF/fragment flags are rejected.
A non-final fragment payload must be a multiple of eight bytes. Non-initial
fragments return without reading transport headers. An initial fragment can yield
transport metadata only when a whole transport header fits; short initial fragment
headers are classified unsupported. A UDP length may exceed the fragment payload
because it refers to the original datagram. IDS and flows exclude all fragmented
packets. There is no reassembly, overlapping-fragment analysis or checksum validation.

## IPv6

The base header is 40 bytes. PacketForge extracts addresses, version, payload
length, original next-header and hop limit, and bounds the declared payload.
The current upper-layer protocol is distinct from the original next-header value.

Hop-by-Hop, Routing and Destination Options use `(HdrExtLen + 1) * 8` bytes;
Authentication Header uses `(PayloadLen + 2) * 4`, with its fixed-field minimum
validated. Fragment headers are eight bytes. The chain is limited to eight
extensions, Hop-by-Hop must be first, and duplicate fragment headers/reserved
fragment fields are rejected. Option contents, routing semantics and authentication
are not verified. ESP and unknown extensions are unsupported.

Fragment offsets/M flag/identification are extracted. Non-initial fragments do not
supply transport fields. Atomic fragments (offset zero, M clear) may be decoded
normally. No Next Header (59) terminates decoding. Jumbograms are unsupported.
ICMPv6 supports type/code and echo request/reply classification, not full neighbor
discovery or router-advertisement interpretation.

## TCP

A minimum 20-byte TCP header must fit inside the IP payload. The data offset is
measured in 32-bit words; values below 5 or headers beyond the IP boundary are
invalid. Source/destination ports, sequence and acknowledgment numbers, header
length, flags and window are copied to host-order fields. TCP options are skipped
within validated boundaries. The six classic flag bits are FIN=0x01, SYN=0x02,
RST=0x04, PSH=0x08, ACK=0x10, URG=0x20.

A detection initiation is SYN set with ACK, FIN and RST clear. That does not prove a
successful handshake. The parser performs no TCP checksum verification, connection
state tracking, sequence acceptance, retransmission reconstruction or application
stream reassembly.

## UDP and ICMP

UDP requires eight bytes, with length >= 8 and length no greater than the IP
payload for an unfragmented datagram. Ports and datagram length are extracted.
UDP checksums and application protocols are not validated. Port 53 is not proof
of a DNS application, and fixture DNS messages are counted as UDP only.

ICMPv4 protocol 1 and ICMPv6 next-header 58 require the common four-byte header.
Echo request/reply messages require eight bytes and code zero. Echo types are
8/0 for IPv4 and 128/129 for IPv6. Other ICMP types receive basic type/code
classification; embedded error packets are not recursively decoded.

## Primary references

- [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html)
- [IPv4 — RFC 791](https://www.rfc-editor.org/rfc/rfc791)
- [IPv6 — RFC 8200](https://www.rfc-editor.org/rfc/rfc8200)
- [TCP — RFC 9293](https://www.rfc-editor.org/rfc/rfc9293)
- [UDP — RFC 768](https://www.rfc-editor.org/rfc/rfc768)
- [ARP — RFC 826](https://www.rfc-editor.org/rfc/rfc826)
- [ICMP — RFC 792](https://www.rfc-editor.org/rfc/rfc792)
- [ICMPv6 — RFC 4443](https://www.rfc-editor.org/rfc/rfc4443)
- [libpcap source and documentation](https://github.com/the-tcpdump-group/libpcap)
