#pragma once
#include "config.hpp"
#include "packet.hpp"
#include <deque>
#include <map>
#include <set>
#include <tuple>
namespace packetforge {
struct FlowKey {
    std::string source, destination;
    std::uint16_t source_port = 0, destination_port = 0;
    std::uint8_t protocol = 0;
    auto tuple() const { return std::tie(source,destination,source_port,destination_port,protocol); }
    bool operator<(const FlowKey& other) const { return tuple()<other.tuple(); }
};
struct Flow {
    FlowKey key;
    std::uint64_t packets=0, observed_bytes=0, wire_bytes=0;
    Timestamp first=0,last=0;
    std::uint8_t tcp_flags=0;
    Json json() const;
};
class FlowTable {
    Config config_;
    std::map<FlowKey,Flow> active_;
    std::deque<Flow> closed_;
    std::set<FlowKey> unique_;
    Timestamp last_sweep_=-1;
    void archive(std::map<FlowKey,Flow>::iterator entry);
public:
    std::uint64_t evictions=0, expired=0, archives_discarded=0;
    bool unique_saturated=false;
    explicit FlowTable(const Config& config) : config_(config) {}
    void observe(const Packet& packet);
    void expire(Timestamp now, bool force=false);
    std::size_t active_count() const { return active_.size(); }
    std::size_t unique_count() const { return unique_.size(); }
    Json json() const;
};
}
