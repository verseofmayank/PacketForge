#include "packetforge/config.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <stdexcept>
namespace packetforge {
namespace {
void keys(const Json& value, const std::set<std::string>& allowed, const std::string& context) {
    if (!value.is_object()) throw std::runtime_error(context + " must be an object");
    for (auto it=value.begin(); it!=value.end(); ++it)
        if (!allowed.count(it.key())) throw std::runtime_error("unknown " + context + " setting: " + it.key());
}
std::int64_t integer(const Json& value, std::int64_t low, std::int64_t high, const std::string& name) {
    if (!value.is_number_integer() || (value.is_number_unsigned() && value.get<std::uint64_t>() > static_cast<std::uint64_t>(high)))
        throw std::runtime_error(name + " must be an integer in range");
    const auto result = value.get<std::int64_t>();
    if (result < low || result > high) throw std::runtime_error(name + " outside range " + std::to_string(low)+".."+std::to_string(high));
    return result;
}
std::string ip(const Json& value) {
    if (!value.is_string()) throw std::runtime_error("IP exclusions/policy addresses must be strings");
    const auto text=value.get<std::string>(); unsigned char buffer[16]{}; char out[INET6_ADDRSTRLEN]{};
    const int family = text.find(':') == std::string::npos ? AF_INET : AF_INET6;
    if (inet_pton(family,text.c_str(),buffer)!=1) throw std::runtime_error("invalid literal IP address: "+text);
    inet_ntop(family,buffer,out,sizeof(out)); return out;
}
std::set<std::string> exclusions(const Json& value) {
    if (!value.is_array() || value.size()>4096) throw std::runtime_error("exclusions must be an array of at most 4096 IPs");
    std::set<std::string> result; for (const auto& entry:value) result.insert(ip(entry)); return result;
}
}
Config Config::defaults() {
    Config c;
    c.rules["POSSIBLE_TCP_PORT_SCAN"] = {true,12,10,30,"MEDIUM",{},{},{}};
    c.rules["HIGH_TCP_SYN_RATE"] = {true,100,10,30,"MEDIUM",{},{},{}};
    c.rules["HIGH_ICMP_ECHO_RATE"] = {true,50,10,30,"LOW",{},{},{}};
    c.rules["SENSITIVE_SERVICE_TRAFFIC"] = {true,1,10,60,"INFO",{22,23,445,3389},{},{}};
    c.rules["CONNECTION_CONCENTRATION"] = {true,40,10,30,"LOW",{},{},{}};
    c.policy = {{"any","any","WOULD_BLOCK",22},{"any","any","WOULD_BLOCK",445},{"any","any","WOULD_ALLOW",-1}};
    return c;
}
Config Config::load(const std::string& path) {
    Config config=defaults(); std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot open rules file: "+path);
    file.seekg(0,std::ios::end); if (file.tellg()>1024*1024) throw std::runtime_error("rules file exceeds 1 MiB"); file.seekg(0);
    Json root;
    // Reject duplicate JSON keys; silently taking the last value is dangerous for rules.
    std::vector<std::set<std::string>> object_keys;
    auto callback=[&](int depth, Json::parse_event_t event, Json& parsed) {
        if (depth>32) throw std::runtime_error("configuration nesting exceeds limit");
        if (event==Json::parse_event_t::object_start) object_keys.emplace_back();
        if (event==Json::parse_event_t::key && !object_keys.back().insert(parsed.get<std::string>()).second)
            throw std::runtime_error("duplicate JSON key: "+parsed.get<std::string>());
        if (event==Json::parse_event_t::object_end) object_keys.pop_back();
        if (object_keys.size()>32) throw std::runtime_error("configuration nesting exceeds limit");
        return true;
    };
    root=Json::parse(file,callback);
    keys(root,{"rules","limits","policy"},"configuration");
    if (root.contains("limits")) {
        const auto& limits=root.at("limits");
        keys(limits,{"max_flows","max_unique_flows","max_talkers","max_rule_keys","max_rule_events","max_alerts","flow_timeout_seconds"},"limits");
        auto set=[&](const char* name,std::size_t& target,std::int64_t maximum) {
            if (limits.contains(name)) target=static_cast<std::size_t>(integer(limits.at(name),1,maximum,name));
        };
        set("max_flows",config.max_flows,100000); set("max_unique_flows",config.max_unique_flows,1000000);
        set("max_talkers",config.max_talkers,100000); set("max_rule_keys",config.max_rule_keys,10000);
        set("max_rule_events",config.max_rule_events,1000000); set("max_alerts",config.max_alerts,100000);
        if (limits.contains("flow_timeout_seconds")) config.flow_timeout_seconds=integer(limits.at("flow_timeout_seconds"),1,86400,"flow_timeout_seconds");
    }
    if (root.contains("rules")) {
        std::set<std::string> names; for (const auto& item:config.rules) names.insert(item.first);
        keys(root.at("rules"),names,"rules");
        for (auto it=root.at("rules").begin(); it!=root.at("rules").end(); ++it) {
            const auto& object=it.value(); auto& rule=config.rules.at(it.key());
            keys(object,{"enabled","threshold","window_seconds","cooldown_seconds","severity","ports","exclude_sources","exclude_destinations"},it.key());
            if (object.contains("enabled")) { if (!object.at("enabled").is_boolean()) throw std::runtime_error("enabled must be boolean"); rule.enabled=object.at("enabled").get<bool>(); }
            if (object.contains("threshold")) rule.threshold=static_cast<std::size_t>(integer(object.at("threshold"),1,10000,"threshold"));
            if (object.contains("window_seconds")) rule.window_seconds=integer(object.at("window_seconds"),1,3600,"window_seconds");
            if (object.contains("cooldown_seconds")) rule.cooldown_seconds=integer(object.at("cooldown_seconds"),0,86400,"cooldown_seconds");
            if (object.contains("severity")) rule.severity=object.at("severity").get<std::string>();
            if (!std::set<std::string>{"INFO","LOW","MEDIUM","HIGH"}.count(rule.severity)) throw std::runtime_error("invalid severity: "+rule.severity);
            if (object.contains("ports")) {
                if (it.key()!="SENSITIVE_SERVICE_TRAFFIC") throw std::runtime_error("ports is only valid for SENSITIVE_SERVICE_TRAFFIC");
                const auto& ports=object.at("ports");
                if (!ports.is_array() || ports.empty() || ports.size()>1024) throw std::runtime_error("ports must contain 1..1024 integers");
                rule.ports.clear(); for (const auto& port:ports) rule.ports.insert(static_cast<std::uint16_t>(integer(port,1,65535,"port")));
            }
            if (object.contains("exclude_sources")) rule.exclude_sources=exclusions(object.at("exclude_sources"));
            if (object.contains("exclude_destinations")) rule.exclude_destinations=exclusions(object.at("exclude_destinations"));
            if (rule.threshold>config.max_rule_events) throw std::runtime_error("rule threshold exceeds max_rule_events");
            if (it.key()=="POSSIBLE_TCP_PORT_SCAN" && rule.threshold<2) throw std::runtime_error("port-scan threshold must be >= 2");
        }
    }
    for (const auto& [id,rule]:config.rules)
        if (rule.enabled && rule.threshold>config.max_rule_events) throw std::runtime_error(id+" threshold exceeds max_rule_events");
    if (root.contains("policy")) {
        if (!root.at("policy").is_array() || root.at("policy").size()>1024) throw std::runtime_error("policy must be an array of at most 1024 rules");
        config.policy.clear();
        for (const auto& item:root.at("policy")) {
            keys(item,{"source","destination","destination_port","action"},"policy"); PolicyRule rule;
            if (item.contains("source") && item.at("source")!="any") rule.source=ip(item.at("source"));
            if (item.contains("destination") && item.at("destination")!="any") rule.destination=ip(item.at("destination"));
            if (item.contains("destination_port")) rule.destination_port=static_cast<int>(integer(item.at("destination_port"),-1,65535,"destination_port"));
            rule.action=item.at("action").get<std::string>();
            if (rule.action!="WOULD_ALLOW" && rule.action!="WOULD_BLOCK") throw std::runtime_error("policy action must be WOULD_ALLOW or WOULD_BLOCK");
            config.policy.push_back(rule);
        }
    }
    return config;
}
Json Config::json() const {
    Json result; result["rules"]=Json::object();
    for (const auto& [id,r]:rules) {
        result["rules"][id]={{"enabled",r.enabled},{"threshold",r.threshold},{"window_seconds",r.window_seconds},
            {"cooldown_seconds",r.cooldown_seconds},{"severity",r.severity},
            {"exclude_sources",r.exclude_sources},{"exclude_destinations",r.exclude_destinations}};
        if (id=="SENSITIVE_SERVICE_TRAFFIC") result["rules"][id]["ports"]=r.ports;
    }
    result["limits"]={{"max_flows",max_flows},{"max_unique_flows",max_unique_flows},{"max_talkers",max_talkers},
        {"max_rule_keys",max_rule_keys},{"max_rule_events",max_rule_events},{"max_alerts",max_alerts},{"flow_timeout_seconds",flow_timeout_seconds}};
    result["policy"]=Json::array();
    for (const auto& r:policy) result["policy"].push_back({{"source",r.source},{"destination",r.destination},{"destination_port",r.destination_port},{"action",r.action}});
    return result;
}
}
