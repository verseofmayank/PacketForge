#include "packetforge/detection.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
namespace packetforge {
void DetectionEngine::trim(State& state, Runtime& runtime, Timestamp now, const RuleConfig& rule) {
    // Half-open window (now-window, now]; events at the left boundary expire.
    while (!state.events.empty() && now-state.events.front().time>=rule.window_seconds*second) {
        state.events.pop_front(); --runtime.events;
    }
}
void DetectionEngine::expire(Timestamp now) {
    if (last_sweep_>=0 && now-last_sweep_<second) return;
    last_sweep_=now;
    for (auto& [id,runtime]:runtime_) {
        const auto& rule=config_.rules.at(id);
        for (auto it=runtime.states.begin(); it!=runtime.states.end();) {
            trim(it->second,runtime,now,rule);
            if (it->second.events.empty() && (!it->second.alerted || now-it->second.last_alert>=rule.cooldown_seconds*second))
                it=runtime.states.erase(it);
            else ++it;
        }
    }
}
std::vector<Json> DetectionEngine::observe(const Packet& p) {
    expire(p.timestamp); std::vector<Json> alerts;
    if (p.status!=ParseStatus::ok || !p.transport || p.fragmented) return alerts;
    for (const auto& [id,rule]:config_.rules) {
        if (!rule.enabled || rule.exclude_sources.count(p.source) || rule.exclude_destinations.count(p.destination)) continue;
        const bool sensitive=id=="SENSITIVE_SERVICE_TRAFFIC", concentration=id=="CONNECTION_CONCENTRATION";
        if (sensitive) {
            if ((p.protocol!=6 && p.protocol!=17) || (!rule.ports.count(p.source_port) && !rule.ports.count(p.destination_port))) continue;
        } else if (id=="HIGH_ICMP_ECHO_RATE") { if (!p.echo_request) continue; }
        else if (!p.syn_attempt()) continue;
        auto& runtime=runtime_.at(id); ++runtime.matched;
        const auto service_port=rule.ports.count(p.destination_port) ? p.destination_port : p.source_port;
        std::string key=concentration ? p.source : p.source+"|"+p.destination;
        if (sensitive) key+="|"+std::to_string(p.protocol)+"|"+std::to_string(service_port);
        auto found=runtime.states.find(key);
        if (found==runtime.states.end()) {
            if (runtime.states.size()>=config_.max_rule_keys) { ++runtime.dropped_keys; continue; }
            found=runtime.states.emplace(key,State{}).first;
        }
        auto& state=found->second; trim(state,runtime,p.timestamp,rule); state.last_seen=p.timestamp;
        if (runtime.events>=config_.max_rule_events) { ++runtime.dropped_events; continue; }
        const auto attempt=p.destination+"|"+std::to_string(p.source_port)+"|"+std::to_string(p.destination_port)+"|"+std::to_string(p.sequence);
        state.events.push_back({p.timestamp,p.destination_port,p.destination,attempt}); ++runtime.events;
        std::set<std::uint16_t> ports;
        std::set<std::string> attempts,destinations;
        std::map<std::string,std::set<std::uint16_t>> ports_by_host;
        for (const auto& event:state.events) {
            ports.insert(event.port); destinations.insert(event.destination);
            if (concentration) { attempts.insert(event.attempt); ports_by_host[event.destination].insert(event.port); }
        }
        const std::size_t count=id=="POSSIBLE_TCP_PORT_SCAN" ? ports.size() : concentration ? attempts.size() : state.events.size();
        if (count<rule.threshold) { state.above=false; continue; }
        // Suppress concentration when its own evidence is scan-shaped. The scan
        // rule remains responsible for distinct-port behavior; thresholds may differ.
        if (concentration) {
            const auto& scan=config_.rules.at("POSSIBLE_TCP_PORT_SCAN"); bool scan_shape=false;
            if (scan.enabled && !scan.exclude_sources.count(p.source))
                for (const auto& [host,host_ports]:ports_by_host)
                    if (!scan.exclude_destinations.count(host) && host_ports.size()>=scan.threshold) scan_shape=true;
            if (scan_shape) { ++runtime.scan_suppressed; continue; }
        }
        if (state.alerted && (p.timestamp-state.last_alert<rule.cooldown_seconds*second || (rule.cooldown_seconds==0 && state.above))) {
            ++runtime.cooldown_suppressed; state.above=true; continue;
        }
        state.alerted=true; state.above=true; state.last_alert=p.timestamp; ++runtime.alerts;
        std::ostringstream alert_id; alert_id << "PF-" << std::setw(6) << std::setfill('0') << next_id_++;
        const std::string title=sensitive ? "Sensitive service traffic observed" : id=="POSSIBLE_TCP_PORT_SCAN" ? "Possible TCP SYN port scan"
            : id=="HIGH_TCP_SYN_RATE" ? "Elevated TCP SYN activity" : id=="HIGH_ICMP_ECHO_RATE" ? "Elevated ICMP echo activity" : "Connection attempts concentrated by source";
        Json port_sample=Json::array(); for (const auto port:ports) { if (port_sample.size()==32) break; port_sample.push_back(port); }
        Json evidence={{"packets_in_window",state.events.size()},{"distinct_destination_ports",ports.size()},
            {"destination_port_sample",port_sample},{"distinct_destinations",destinations.size()},
            {"protocol",p.protocol_name()},{"window_start",iso_time(std::max<Timestamp>(0,p.timestamp-rule.window_seconds*second))},
            {"window_end",iso_time(p.timestamp)},{"window_interval","(start, end]"}};
        if (concentration) evidence["distinct_connection_attempts"]=attempts.size();
        if (sensitive) evidence["observed_service_port"]=service_port;
        if (p.protocol==6) evidence["trigger_tcp_flags"]=p.tcp_flags;
        const std::string limitation=sensitive ? "Informational observation only. Service access can be authorized; port number does not prove application identity."
            : id=="HIGH_ICMP_ECHO_RATE" ? "Heuristic only. Monitoring and diagnostics can generate echo bursts."
            : id=="HIGH_TCP_SYN_RATE" ? "Heuristic only. Retransmissions, busy clients and capture duplicates can raise SYN counts; this does not confirm denial of service."
            : "Heuristic only. Authorized scanning, retries, NAT aggregation and incomplete visibility can produce similar metadata; no compromise is confirmed.";
        alerts.push_back({{"alert_id",alert_id.str()},{"rule_id",id},{"title",title},{"timestamp",iso_time(p.timestamp)},
            {"timestamp_ns",p.timestamp},{"severity",rule.severity},{"source",p.source},
            {"destination",concentration && destinations.size()>1 ? "multiple observed destinations" : p.destination},
            {"source_port",p.source_port},{"destination_port",p.destination_port},{"detection_window_seconds",rule.window_seconds},
            {"observed_count",count},{"threshold",rule.threshold},{"evidence",evidence},{"confidence","metadata heuristic"},
            {"limitations",limitation},{"recommendation",sensitive ? "Confirm that service access matches policy and inspect authorized service logs."
                : "Validate against the traffic baseline, approved scans and endpoint/service logs before responding."},
            {"mitre_technique",id=="POSSIBLE_TCP_PORT_SCAN" ? Json("T1046 - Network Service Discovery") : Json(nullptr)}});
    }
    return alerts;
}
Json DetectionEngine::counters() const {
    Json counters=Json::object();
    for (const auto& [id,runtime]:runtime_) counters[id]={{"matched_packets",runtime.matched},{"alerts",runtime.alerts},
        {"cooldown_suppressed",runtime.cooldown_suppressed},{"scan_overlap_suppressed",runtime.scan_suppressed},
        {"dropped_events",runtime.dropped_events},{"dropped_keys",runtime.dropped_keys},
        {"retained_events",runtime.events},{"retained_keys",runtime.states.size()}};
    return counters;
}
}
