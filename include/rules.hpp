#pragma once
#include "packetforge/config.hpp"
#include "packetforge/packet.hpp"
namespace packetforge {
// Original first-match source/destination/port logic, now explicitly simulation.
inline std::string evaluate_policy(const Packet& packet, const std::vector<PolicyRule>& rules) {
    for (const auto& rule : rules) {
        if ((rule.source == "any" || rule.source == packet.source)
            && (rule.destination == "any" || rule.destination == packet.destination)
            && (rule.destination_port == -1 || (packet.transport && (packet.protocol == 6 || packet.protocol == 17)
                && rule.destination_port == packet.destination_port))) return rule.action;
    }
    return "WOULD_ALLOW";
}
}
