#include "packetforge/analysis.hpp"
#include <iomanip>
#include <ostream>
#include <stdexcept>
namespace packetforge {
void Analysis::observe(const Packet& p,const std::function<void(const Json&)>& emit) {
    if (p.timestamp<0 || p.timestamp<previous_) throw std::runtime_error("analysis requires chronological nonnegative timestamps");
    previous_=p.timestamp; statistics.observe(p); flows.observe(p);
    if (ids_) for (auto& alert:detection.observe(p)) {
        ++total_alerts; ++alert_counts[alert.at("rule_id").get<std::string>()];
        if (emit) emit(alert);
        if (alerts.size()<config_.max_alerts) alerts.push_back(std::move(alert)); else ++alerts_not_retained;
    }
}
Json Analysis::report(const std::string& mode,const std::string& source,const CaptureResult& capture) const {
    auto stats=statistics.json(); stats["active_flows"]=flows.active_count(); stats["unique_flows"]=flows.unique_count();
    stats["unique_flow_count_is_lower_bound"]=flows.unique_saturated; stats["flow_evictions"]=flows.evictions;
    stats["expired_flows"]=flows.expired; stats["flow_archives_discarded"]=flows.archives_discarded;
    stats["total_ids_alerts"]=total_alerts; stats["alerts_by_classification"]=alert_counts; stats["alerts_not_retained"]=alerts_not_retained;
    return {{"project","PacketForge"},{"author","Mayank Kumar Karn"},{"schema_version",1},
        {"metadata",{{"mode",mode},{"source",source},{"ids_enabled",ids_},{"export_timestamp",iso_time(now_timestamp())},
            {"first_packet",statistics.packets ? Json(iso_time(statistics.first)) : Json(nullptr)},
            {"last_packet",statistics.packets ? Json(iso_time(statistics.last)) : Json(nullptr)},
            {"kernel_drops",capture.kernel_drops},{"interrupted",capture.interrupted},{"capture_packets",capture.packets}}},
        {"statistics",stats},{"rules",config_.json()},{"rule_counters",detection.counters()},
        {"flows",flows.json()},{"alerts",alerts},
        {"limitations",Json::array({"Passive metadata analysis; firewall decisions are simulation and do not block traffic.",
            "Heuristic alerts are observations, not confirmed attacks. Tune demonstration thresholds to your baseline.",
            "Directional TCP/UDP five-tuples only; no TCP stream or IP fragment reassembly, application inspection or checksum validation.",
            "Only classic Ethernet PCAP; PCAPNG and other link types are rejected. Nonchronological files are rejected.",
            "NIC offloads, loopback duplicates, dropped packets and capture position affect visibility and rates.",
            "Bounded state can omit flows, talkers, alerts and rule evidence. Review saturation, eviction and drop counters.",
            "Protocol counters overlap layers; rates use the first-to-last observed packet interval, not capture wall time."})}};
}
void Analysis::summary(std::ostream& out) const {
    const auto data=statistics.json();
    out << "\nPacketForge | Investigation summary\nPackets: " << statistics.packets << " | Observed bytes: " << statistics.observed_bytes
        << " | Wire bytes: " << statistics.wire_bytes << '\n';
    out << "Truncated: " << statistics.truncated << " | Malformed: " << statistics.malformed << " | Unsupported: " << statistics.unsupported << '\n';
    out << "Protocols:"; for (const auto& [name,count]:statistics.protocols) out << ' ' << name << '=' << count; out << '\n';
    out << "Observation interval: " << std::fixed << std::setprecision(3) << statistics.duration() << " s | Packets/s: "
        << (data["packets_per_second"].is_null() ? "n/a" : data["packets_per_second"].dump()) << " | Bytes/s: "
        << (data["bytes_per_second"].is_null() ? "n/a" : data["bytes_per_second"].dump()) << '\n';
    out << "Unique directional flows: " << flows.unique_count() << (flows.unique_saturated ? " (lower bound)" : "")
        << " | Active: " << flows.active_count() << " | IDS alerts: " << total_alerts << '\n';
    for (const auto& field:{"top_sources","top_destinations","destination_ports"}) {
        out << field << ':';
        for (const auto& item:data[field]) out << ' ' << (item.contains("address") ? item["address"].get<std::string>() : item["port"].dump()) << '=' << item["packets"];
        out << '\n';
    }
    for (const auto& [id,count]:alert_counts) out << "  " << id << ": " << count << '\n';
    if (flows.evictions || flows.archives_discarded || statistics.omitted_sources || statistics.omitted_destinations || alerts_not_retained)
        out << "Warning: retention limits reached; review report counters for omitted evidence.\n";
    const auto counters=detection.counters();
    for (const auto& [id,counter]:counters.items())
        if (counter["dropped_keys"].get<std::uint64_t>() || counter["dropped_events"].get<std::uint64_t>())
            out << "Warning: " << id << " hit a state limit; detections can be missed.\n";
}
}
