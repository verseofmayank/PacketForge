#pragma once
#include "packet.hpp"
#include <functional>
#include <string>
namespace packetforge {
using PacketConsumer = std::function<void(const Packet&)>;
struct CaptureOptions {
    std::string interface;
    std::uint64_t count = 0;
    double duration = 0;
    bool promiscuous = false;
};
struct CaptureResult {
    std::uint64_t packets = 0, kernel_drops = 0;
    bool interrupted = false;
};
void list_interfaces();
CaptureResult analyze_pcap(const std::string& path, const PacketConsumer& consume, std::uint64_t limit = 0);
CaptureResult capture_live(const CaptureOptions& options, const PacketConsumer& consume,
                           const std::function<void()>& tick = {});
}
