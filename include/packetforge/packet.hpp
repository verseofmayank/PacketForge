#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace packetforge {
using Timestamp = std::int64_t; // Unix nanoseconds; PCAP timestamps drive offline windows.
constexpr Timestamp second = 1000000000LL;
enum class ParseStatus { ok, truncated, malformed, unsupported };
const char* status_name(ParseStatus status);

// Decoded host-order values, never overlays of an untrusted network buffer.
struct Packet {
    Timestamp timestamp = 0;
    std::uint32_t captured_length = 0, wire_length = 0;
    ParseStatus status = ParseStatus::ok;
    std::string detail;
    bool capture_truncated = false, ethernet = false, arp = false;
    bool ipv4 = false, ipv6 = false, transport = false, fragmented = false;
    std::string source_mac, destination_mac, source, destination;
    std::uint16_t ethertype = 0;
    std::vector<std::uint16_t> vlan_ids;
    std::uint8_t version = 0, ip_header_length = 0, ttl = 0, protocol = 0, next_header = 0;
    std::uint16_t ip_total_length = 0, ipv6_payload_length = 0;
    std::uint16_t fragment_offset = 0, ip_id = 0;
    std::uint32_t ipv6_fragment_id = 0;
    bool more_fragments = false, dont_fragment = false;
    std::uint16_t source_port = 0, destination_port = 0;
    std::uint32_t sequence = 0, acknowledgment = 0;
    std::uint8_t tcp_header_length = 0, tcp_flags = 0;
    std::uint16_t tcp_window = 0, udp_length = 0;
    std::uint8_t icmp_type = 0, icmp_code = 0;
    bool echo_request = false, echo_reply = false;
    std::uint16_t arp_opcode = 0;
    std::string arp_sender_hardware, arp_target_hardware;
    bool syn_attempt() const { return transport && protocol == 6 && (tcp_flags & 0x02) && !(tcp_flags & 0x15); }
    std::string protocol_name() const;
};
Packet parse_packet(const std::uint8_t* bytes, std::size_t captured,
                    std::uint32_t wire_length, Timestamp timestamp);
std::string iso_time(Timestamp timestamp);
Timestamp now_timestamp();
}
