#include "packetforge/capture.hpp"
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <pcap/pcap.h>
#include <stdexcept>
namespace packetforge {
CaptureResult analyze_pcap(const std::string& path, const PacketConsumer& consume, std::uint64_t limit) {
    // Deliberately support classic PCAP only, despite libpcap accepting some PCAPNG files.
    std::ifstream input(path, std::ios::binary); std::array<unsigned char, 4> magic{};
    if (!input.read(reinterpret_cast<char*>(magic.data()), 4)) throw std::runtime_error("cannot read PCAP header: " + path);
    const bool classic = magic == std::array<unsigned char,4>{0xd4,0xc3,0xb2,0xa1}
        || magic == std::array<unsigned char,4>{0xa1,0xb2,0xc3,0xd4}
        || magic == std::array<unsigned char,4>{0x4d,0x3c,0xb2,0xa1}
        || magic == std::array<unsigned char,4>{0xa1,0xb2,0x3c,0x4d};
    if (!classic) throw std::runtime_error("only standard PCAP is supported; PCAPNG is not supported");
    char error[PCAP_ERRBUF_SIZE]{};
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(
        pcap_open_offline_with_tstamp_precision(path.c_str(), PCAP_TSTAMP_PRECISION_NANO, error), pcap_close);
    if (!handle) throw std::runtime_error(std::string("PCAP: ") + error);
    if (pcap_datalink(handle.get()) != DLT_EN10MB) throw std::runtime_error("unsupported PCAP link type; Ethernet (DLT_EN10MB) required");
    CaptureResult result; Timestamp previous = -1;
    while (!limit || result.packets < limit) {
        pcap_pkthdr* header = nullptr; const u_char* bytes = nullptr;
        const int status = pcap_next_ex(handle.get(), &header, &bytes);
        if (status == -2) break;
        if (status == -1) throw std::runtime_error(std::string("PCAP read error: ") + pcap_geterr(handle.get()));
        if (status == 0) continue;
        const auto secs = header->ts.tv_sec, nanos = header->ts.tv_usec;
        if (secs < 0 || nanos < 0 || nanos >= second || secs > (std::numeric_limits<Timestamp>::max()-nanos)/second)
            throw std::runtime_error("PCAP timestamp outside supported Unix nanosecond range");
        const Timestamp timestamp = secs * second + nanos;
        if (timestamp < previous) throw std::runtime_error("PCAP timestamps are not chronological; sort capture before analysis");
        previous = timestamp;
        if (header->caplen > 16U*1024U*1024U || header->caplen > header->len)
            throw std::runtime_error("invalid PCAP captured/wire length");
        consume(parse_packet(bytes, header->caplen, header->len, timestamp)); ++result.packets;
    }
    return result;
}
}
