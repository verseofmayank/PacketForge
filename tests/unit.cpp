#include "packetforge/packet.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace packetforge;
namespace {
unsigned checks = 0;
void check(bool condition, const char* message) { ++checks; if (!condition) throw std::runtime_error(message); }
void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t value) { b[o] = static_cast<std::uint8_t>(value >> 8); b[o+1] = static_cast<std::uint8_t>(value); }
std::vector<std::uint8_t> tcp() {
    std::vector<std::uint8_t> b(54); put16(b,12,0x0800); b[14]=0x45; put16(b,16,40); b[22]=64; b[23]=6;
    b[26]=192; b[28]=2; b[29]=1; b[30]=198; b[31]=51; b[32]=100; b[33]=2;
    put16(b,34,12345); put16(b,36,443); b[38]=0x12; b[39]=0x34; b[40]=0x56; b[41]=0x78;
    b[46]=0x50; b[47]=2; put16(b,48,4096); return b;
}
Packet parse(const std::vector<std::uint8_t>& b) { return parse_packet(b.data(), b.size(), static_cast<std::uint32_t>(b.size()), 0); }
void parser_tests() {
    auto b=tcp(); auto p=parse(b);
    check(p.status==ParseStatus::ok && p.ethernet && p.ipv4 && p.transport, "Ethernet IPv4 TCP");
    check(p.source=="192.0.2.1" && p.destination=="198.51.100.2", "addresses");
    check(p.source_port==12345 && p.destination_port==443 && p.sequence==0x12345678 && p.tcp_window==4096, "network order");
    check(p.syn_attempt() && p.tcp_header_length==20 && p.ttl==64, "TCP fields");
    for (std::size_t n=0; n<b.size(); ++n) check(parse_packet(b.data(),n,54,0).status==ParseStatus::truncated, "truncated prefix");
    b[14]=0x44; check(parse(b).status==ParseStatus::malformed,"IHL minimum"); b=tcp();
    b[46]=0x40; check(parse(b).status==ParseStatus::malformed,"TCP offset minimum"); b=tcp();
    put16(b,16,20); check(parse(b).status==ParseStatus::malformed,"Ethernet padding cannot supply TCP header"); b=tcp();
    put16(b,20,1); p=parse(b); check(p.fragmented && p.fragment_offset==8 && !p.transport,"non-initial IPv4 fragment");
    b=tcp(); b.insert(b.begin()+34,4,0); b[14]=0x46; put16(b,16,44); check(parse(b).destination_port==443,"IPv4 options");
    b=tcp(); b.insert(b.begin()+12,{0x81,0,0,42}); p=parse(b); check(p.vlan_ids.size()==1 && p.vlan_ids[0]==42 && p.destination_port==443,"VLAN");
    b=tcp(); b[23]=99; check(parse(b).status==ParseStatus::unsupported,"unsupported protocol");
    check(parse_packet(nullptr,0,0,0).status==ParseStatus::truncated,"empty buffer");
}
}
int main() { try { parser_tests(); std::cout << checks << " checks passed\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; } }
