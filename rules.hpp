#pragma once
#include <cstdint>
#include <string>
#include <vector>

enum class Action { ALLOW, DROP };

struct Rule {
    std::string src_ip;   // "any" = match all
    std::string dst_ip;   // "any" = match all
    int dst_port;         // -1 = match all
    Action action;
};

// Simple rule table — checked top to bottom, first match wins
inline std::vector<Rule> ruleTable = {
    { "any", "any", 22,  Action::DROP  },   // block SSH traffic
    { "any", "any", 445, Action::DROP  },   // block SMB (common attack port)
    { "any", "any", -1,  Action::ALLOW }    // default: allow everything else
};
