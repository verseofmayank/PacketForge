#pragma once
#include "config.hpp"
#include "packet.hpp"
#include <map>
namespace packetforge {
class Statistics {
    std::size_t max_talkers_;
    void talker(std::map<std::string,std::uint64_t>& table,const std::string& address,std::uint64_t& omitted);
public:
    std::uint64_t packets=0,observed_bytes=0,wire_bytes=0,truncated=0,malformed=0,unsupported=0;
    std::uint64_t omitted_sources=0,omitted_destinations=0;
    Timestamp first=0,last=0;
    std::map<std::string,std::uint64_t> protocols,sources,destinations;
    std::map<std::uint16_t,std::uint64_t> ports;
    explicit Statistics(std::size_t maximum) : max_talkers_(maximum) {}
    void observe(const Packet& p);
    double duration() const;
    Json json() const;
};
}
