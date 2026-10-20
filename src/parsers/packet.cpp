#include "packetforge/packet.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>

namespace packetforge {
namespace {
struct Failure { ParseStatus status; const char* reason; };
class Decoder {
    const std::uint8_t* data_;
    std::size_t end_;
public:
    Decoder(const std::uint8_t* data, std::size_t size) : data_(data), end_(size) {}
    void need(std::size_t offset, std::size_t length) const {
        if (offset > end_ || length > end_ - offset)
            throw Failure{ParseStatus::truncated, "captured header incomplete"};
    }
    void limit(std::size_t end) { end_ = std::min(end_, end); }
    std::uint8_t u8(std::size_t i) const { need(i, 1); return data_[i]; }
    std::uint16_t u16(std::size_t i) const {
        need(i, 2); return static_cast<std::uint16_t>((data_[i] << 8) | data_[i+1]);
    }
    std::uint32_t u32(std::size_t i) const {
        need(i, 4); return (std::uint32_t(data_[i]) << 24) | (std::uint32_t(data_[i+1]) << 16)
            | (std::uint32_t(data_[i+2]) << 8) | data_[i+3];
    }
    std::string mac(std::size_t i) const {
        need(i, 6); char out[18];
        std::snprintf(out, sizeof(out), "%02x:%02x:%02x:%02x:%02x:%02x", data_[i], data_[i+1],
                      data_[i+2], data_[i+3], data_[i+4], data_[i+5]);
        return out;
    }
    std::string ip(std::size_t i, bool v6) const {
        need(i, v6 ? 16 : 4); char out[INET6_ADDRSTRLEN]{};
        inet_ntop(v6 ? AF_INET6 : AF_INET, data_ + i, out, sizeof(out)); return out;
    }
};
void malformed(bool condition, const char* reason) {
    if (condition) throw Failure{ParseStatus::malformed, reason};
}
void unsupported(const char* reason) { throw Failure{ParseStatus::unsupported, reason}; }
}
const char* status_name(ParseStatus status) {
    switch (status) {
    case ParseStatus::ok: return "ok";
    case ParseStatus::truncated: return "truncated";
    case ParseStatus::malformed: return "malformed";
    case ParseStatus::unsupported: return "unsupported";
    }
    return "unsupported";
}
std::string Packet::protocol_name() const {
    if (arp) return "ARP";
    if (ipv4 || ipv6) {
        if (protocol == 6) return "TCP";
        if (protocol == 17) return "UDP";
        if (protocol == 1 || protocol == 58) return "ICMP";
        return ipv6 ? "IPv6-other" : "IPv4-other";
    }
    return "Ethernet-other";
}
Packet parse_packet(const std::uint8_t* data, std::size_t size, std::uint32_t wire, Timestamp ts) {
    Packet p; p.timestamp = ts; p.wire_length = wire;
    p.captured_length = static_cast<std::uint32_t>(std::min<std::size_t>(size, UINT32_MAX));
    p.capture_truncated = size < wire;
    Decoder b(data, size);
    try {
        malformed(size > wire || size > UINT32_MAX || (!data && size), "invalid capture/wire length");
        b.need(0, 14); p.ethernet = true;
        p.destination_mac = b.mac(0); p.source_mac = b.mac(6); p.ethertype = b.u16(12);
        std::size_t o = 14;
        while (p.ethertype == 0x8100 || p.ethertype == 0x88a8) {
            if (p.vlan_ids.size() == 2) unsupported("more than two VLAN tags");
            b.need(o, 4); p.vlan_ids.push_back(b.u16(o) & 0x0fff);
            p.ethertype = b.u16(o+2); o += 4;
        }
        if (p.ethertype == 0x0806) {
            b.need(o, 8); p.arp_opcode = b.u16(o+6);
            const auto hlen = b.u8(o+4), plen = b.u8(o+5);
            b.need(o+8, 2U * hlen + 2U * plen);
            if (b.u16(o) != 1 || b.u16(o+2) != 0x0800 || hlen != 6 || plen != 4)
                unsupported("ARP address format is not Ethernet/IPv4");
            p.arp = true; p.arp_sender_hardware = b.mac(o+8); p.source = b.ip(o+14, false);
            p.arp_target_hardware = b.mac(o+18); p.destination = b.ip(o+24, false);
            return p;
        }
        std::size_t end = 0;
        if (p.ethertype == 0x0800) {
            b.need(o, 20); p.version = b.u8(o) >> 4; p.ip_header_length = (b.u8(o) & 15) * 4;
            malformed(p.version != 4 || p.ip_header_length < 20, "invalid IPv4 version or IHL");
            p.ip_total_length = b.u16(o+2);
            malformed(p.ip_total_length < p.ip_header_length, "IPv4 total length smaller than header");
            malformed(p.ip_total_length > wire - o, "IPv4 total length exceeds wire frame");
            b.need(o, p.ip_header_length); p.ipv4 = true;
            p.source = b.ip(o+12, false); p.destination = b.ip(o+16, false);
            p.ttl = b.u8(o+8); p.protocol = b.u8(o+9); p.next_header = p.protocol; p.ip_id = b.u16(o+4);
            const auto fragment = b.u16(o+6);
            p.fragment_offset = static_cast<std::uint16_t>((fragment & 0x1fff) * 8);
            p.more_fragments = (fragment & 0x2000) != 0; p.dont_fragment = (fragment & 0x4000) != 0;
            p.fragmented = p.more_fragments || p.fragment_offset != 0;
            malformed((fragment & 0x8000) || (p.dont_fragment && p.fragmented), "invalid IPv4 fragmentation flags");
            malformed(p.more_fragments && ((p.ip_total_length - p.ip_header_length) % 8 != 0),
                      "non-final IPv4 fragment payload not multiple of eight");
            end = o + p.ip_total_length; b.need(o, p.ip_total_length); b.limit(end); o += p.ip_header_length;
            if (p.fragment_offset) { p.detail = "non-initial IPv4 fragment; transport skipped"; return p; }
        } else if (p.ethertype == 0x86dd) {
            b.need(o, 40); p.version = b.u8(o) >> 4;
            malformed(p.version != 6, "invalid IPv6 version"); p.ipv6 = true;
            p.source = b.ip(o+8, true); p.destination = b.ip(o+24, true);
            p.ipv6_payload_length = b.u16(o+4); p.next_header = b.u8(o+6); p.protocol = p.next_header; p.ttl = b.u8(o+7);
            if (p.ipv6_payload_length == 0 && p.protocol != 59) unsupported("IPv6 jumbograms/zero-length payload unsupported");
            malformed(40U + p.ipv6_payload_length > wire - o, "IPv6 payload exceeds wire frame");
            end = o + 40 + p.ipv6_payload_length; b.need(o, 40 + p.ipv6_payload_length); b.limit(end); o += 40;
            unsigned extensions = 0; bool seen_fragment = false;
            while (p.protocol == 0 || p.protocol == 43 || p.protocol == 60 || p.protocol == 44 || p.protocol == 51) {
                if (++extensions > 8) unsupported("IPv6 extension chain limit reached");
                malformed(p.protocol == 0 && extensions != 1, "hop-by-hop header must be first");
                if (end - o < 2) throw Failure{ParseStatus::malformed, "IPv6 extension exceeds payload"};
                std::size_t length = (std::size_t(b.u8(o+1)) + 1) * 8;
                if (p.protocol == 51) length = (std::size_t(b.u8(o+1)) + 2) * 4;
                if (p.protocol == 44) {
                    malformed(seen_fragment, "duplicate IPv6 fragment header"); seen_fragment = true; length = 8;
                    malformed(end - o < length, "IPv6 fragment exceeds payload"); b.need(o, length);
                    const auto bits = b.u16(o+2);
                    malformed((bits & 6) != 0 || b.u8(o+1) != 0, "invalid IPv6 fragment reserved bits");
                    p.fragment_offset = bits & 0xfff8; p.more_fragments = bits & 1;
                    p.fragmented = p.fragment_offset != 0 || p.more_fragments; p.ipv6_fragment_id = b.u32(o+4);
                    malformed(p.more_fragments && ((end-o-8) % 8 != 0), "non-final IPv6 fragment length");
                }
                malformed(length > end - o, "IPv6 extension exceeds payload"); b.need(o, length);
                p.protocol = b.u8(o); o += length;
                if (p.fragment_offset) { p.detail = "non-initial IPv6 fragment; transport skipped"; return p; }
            }
            if (p.protocol == 59) { p.detail = "IPv6 no next header"; return p; }
        } else { unsupported(p.ethertype <= 1500 ? "IEEE 802.3 LLC unsupported" : "EtherType unsupported"); }
        const auto remaining = end - o;
        auto require_transport = [&](std::size_t n) {
            if (remaining < n && p.fragmented) unsupported("initial fragment lacks complete transport header");
            malformed(remaining < n, "transport header exceeds IP payload"); b.need(o, n);
        };
        if (p.protocol == 6) {
            require_transport(20); p.tcp_header_length = (b.u8(o+12) >> 4) * 4;
            malformed(p.tcp_header_length < 20, "invalid TCP data offset"); require_transport(p.tcp_header_length);
            p.source_port = b.u16(o); p.destination_port = b.u16(o+2);
            p.sequence = b.u32(o+4); p.acknowledgment = b.u32(o+8);
            p.tcp_flags = b.u8(o+13); p.tcp_window = b.u16(o+14); p.transport = true;
        } else if (p.protocol == 17) {
            require_transport(8); p.udp_length = b.u16(o+4);
            malformed(p.udp_length < 8 || (!p.fragmented && p.udp_length > remaining), "invalid UDP length");
            p.source_port = b.u16(o); p.destination_port = b.u16(o+2); p.transport = true;
        } else if ((p.ipv4 && p.protocol == 1) || (p.ipv6 && p.protocol == 58)) {
            require_transport(4); p.icmp_type = b.u8(o); p.icmp_code = b.u8(o+1);
            p.echo_request = p.icmp_code == 0 && p.icmp_type == (p.ipv6 ? 128 : 8);
            p.echo_reply = p.icmp_code == 0 && p.icmp_type == (p.ipv6 ? 129 : 0);
            if (p.echo_request || p.echo_reply) require_transport(8);
            p.transport = true;
        } else unsupported("IP protocol/extension unsupported (including ESP)");
    } catch (const Failure& error) { p.status = error.status; p.detail = error.reason; p.transport = false; }
    return p;
}
Timestamp now_timestamp() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
std::string iso_time(Timestamp timestamp) {
    const auto whole = timestamp / second;
    const std::time_t seconds = static_cast<std::time_t>(whole);
    std::tm tm{}; if (!gmtime_r(&seconds, &tm)) return "invalid timestamp";
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(9) << std::setfill('0')
        << (timestamp % second) << 'Z'; return out.str();
}
}
