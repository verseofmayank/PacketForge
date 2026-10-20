#pragma once
#include "config.hpp"
#include "packet.hpp"
#include <deque>
#include <map>
#include <vector>
namespace packetforge {
class DetectionEngine {
    struct Event { Timestamp time; std::uint16_t port; std::string destination, attempt; };
    struct State {
        std::deque<Event> events;
        Timestamp last_seen=0,last_alert=0;
        bool alerted=false, above=false;
    };
    struct Runtime {
        std::map<std::string,State> states;
        std::size_t events=0;
        std::uint64_t matched=0,alerts=0,cooldown_suppressed=0,scan_suppressed=0,dropped_events=0,dropped_keys=0;
    };
    Config config_;
    std::map<std::string,Runtime> runtime_;
    Timestamp last_sweep_=-1;
    std::uint64_t next_id_=1;
    void trim(State& state, Runtime& runtime, Timestamp now, const RuleConfig& rule);
public:
    explicit DetectionEngine(const Config& config) : config_(config) {
        for (const auto& [id,rule]:config.rules) { (void)rule; runtime_.emplace(id,Runtime{}); }
    }
    void expire(Timestamp now);
    std::vector<Json> observe(const Packet& packet);
    Json counters() const;
};
}
