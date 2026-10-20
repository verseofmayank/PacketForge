#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
namespace packetforge {
using Json = nlohmann::json;
struct RuleConfig {
    bool enabled = true;
    std::size_t threshold = 1;
    std::int64_t window_seconds = 10, cooldown_seconds = 30;
    std::string severity = "MEDIUM";
    std::set<std::uint16_t> ports;
    std::set<std::string> exclude_sources, exclude_destinations;
};
struct PolicyRule {
    std::string source = "any", destination = "any", action = "WOULD_ALLOW";
    int destination_port = -1;
};
struct Config {
    std::map<std::string, RuleConfig> rules;
    std::vector<PolicyRule> policy;
    std::size_t max_flows = 4096, max_unique_flows = 65536, max_talkers = 4096;
    std::size_t max_rule_keys = 1024, max_rule_events = 50000, max_alerts = 10000;
    std::int64_t flow_timeout_seconds = 60;
    static Config defaults();
    static Config load(const std::string& path);
    Json json() const;
};
}
