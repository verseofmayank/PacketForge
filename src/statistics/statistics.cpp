#include "packetforge/statistics.hpp"
#include <algorithm>
namespace packetforge {
void Statistics::talker(std::map<std::string,std::uint64_t>& table,const std::string& address,std::uint64_t& omitted) {
    if (address.empty()) return;
    auto it=table.find(address);
    if (it!=table.end()) ++it->second;
    else if (table.size()<max_talkers_) table[address]=1;
    else ++omitted;
}
void Statistics::observe(const Packet& p) {
    if (!packets) first=p.timestamp;
    last=p.timestamp; ++packets; observed_bytes+=p.captured_length; wire_bytes+=p.wire_length;
    if (p.capture_truncated || p.status==ParseStatus::truncated) ++truncated;
    if (p.status==ParseStatus::malformed) ++malformed;
    if (p.status==ParseStatus::unsupported) ++unsupported;
    if (p.ethernet) ++protocols["Ethernet"];
    if (p.arp) ++protocols["ARP"];
    if (p.ipv4) ++protocols["IPv4"];
    if (p.ipv6) ++protocols["IPv6"];
    if (p.transport) ++protocols[p.protocol_name()];
    if (p.fragmented) ++protocols["Fragmented IP"];
    talker(sources,p.source,omitted_sources); talker(destinations,p.destination,omitted_destinations);
    if (p.transport && (p.protocol==6 || p.protocol==17)) ++ports[p.destination_port];
}
double Statistics::duration() const { return packets ? static_cast<double>(last-first)/second : 0; }
Json Statistics::json() const {
    auto top=[](const auto& values) {
        std::vector<std::pair<std::string,std::uint64_t>> rows(values.begin(),values.end());
        std::sort(rows.begin(),rows.end(),[](const auto& a,const auto& b) { return a.second!=b.second ? a.second>b.second : a.first<b.first; });
        Json out=Json::array();
        for (std::size_t i=0;i<std::min<std::size_t>(rows.size(),10);++i) out.push_back({{"address",rows[i].first},{"packets",rows[i].second}});
        return out;
    };
    Json destination_ports=Json::array();
    std::vector<std::pair<std::uint16_t,std::uint64_t>> ranked(ports.begin(),ports.end());
    std::sort(ranked.begin(),ranked.end(),[](const auto& a,const auto& b) { return a.second!=b.second ? a.second>b.second : a.first<b.first; });
    for (std::size_t i=0;i<std::min<std::size_t>(ranked.size(),10);++i) destination_ports.push_back({{"port",ranked[i].first},{"packets",ranked[i].second}});
    const auto seconds=duration();
    return {{"packets",packets},{"observed_bytes",observed_bytes},{"wire_bytes",wire_bytes},{"truncated",truncated},
        {"malformed",malformed},{"unsupported",unsupported},{"duration_seconds",seconds},
        {"packets_per_second",seconds>0 ? Json(static_cast<double>(packets)/seconds) : Json(nullptr)},
        {"bytes_per_second",seconds>0 ? Json(static_cast<double>(observed_bytes)/seconds) : Json(nullptr)},
        {"protocols",protocols},{"top_sources",top(sources)},{"top_destinations",top(destinations)},
        {"destination_ports",destination_ports},{"omitted_source_observations",omitted_sources},
        {"omitted_destination_observations",omitted_destinations}};
}
}
