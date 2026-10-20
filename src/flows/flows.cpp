#include "packetforge/flows.hpp"
#include <algorithm>
namespace packetforge {
Json Flow::json() const {
    return {{"source",key.source},{"destination",key.destination},{"source_port",key.source_port},
        {"destination_port",key.destination_port},{"protocol",key.protocol},{"packets",packets},
        {"observed_bytes",observed_bytes},{"wire_bytes",wire_bytes},{"first_seen",iso_time(first)},
        {"last_seen",iso_time(last)},{"first_seen_ns",first},{"last_seen_ns",last},
        {"duration_seconds",static_cast<double>(last-first)/second},{"tcp_flags",tcp_flags},
        {"direction","source_to_destination"}};
}
void FlowTable::archive(std::map<FlowKey,Flow>::iterator entry) {
    if (closed_.size()==config_.max_flows) { closed_.pop_front(); ++archives_discarded; }
    closed_.push_back(entry->second); active_.erase(entry);
}
void FlowTable::expire(Timestamp now, bool force) {
    if (!force && last_sweep_>=0 && now-last_sweep_<second) return;
    last_sweep_=now;
    for (auto it=active_.begin();it!=active_.end();) {
        if (now-it->second.last>=config_.flow_timeout_seconds*second) { auto old=it++; archive(old); ++expired; }
        else ++it;
    }
}
void FlowTable::observe(const Packet& p) {
    expire(p.timestamp);
    if (p.status!=ParseStatus::ok || !p.transport || p.fragmented || (p.protocol!=6 && p.protocol!=17)) return;
    FlowKey key{p.source,p.destination,p.source_port,p.destination_port,p.protocol};
    if (!unique_.count(key)) {
        if (unique_.size()<config_.max_unique_flows) unique_.insert(key); else unique_saturated=true;
    }
    auto it=active_.find(key);
    if (it==active_.end()) {
        if (active_.size()==config_.max_flows) {
            auto oldest=std::min_element(active_.begin(),active_.end(),[](const auto& a,const auto& b){ return a.second.last<b.second.last; });
            archive(oldest); ++evictions;
        }
        it=active_.emplace(key,Flow{key,0,0,0,p.timestamp,p.timestamp,0}).first;
    }
    auto& f=it->second; ++f.packets; f.observed_bytes+=p.captured_length; f.wire_bytes+=p.wire_length;
    f.last=p.timestamp; f.tcp_flags|=p.tcp_flags;
}
Json FlowTable::json() const {
    Json flows=Json::array();
    for (const auto& flow:closed_) { auto j=flow.json(); j["active"]=false; flows.push_back(std::move(j)); }
    for (const auto& [key,flow]:active_) { (void)key; auto j=flow.json(); j["active"]=true; flows.push_back(std::move(j)); }
    return flows;
}
}
