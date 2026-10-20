#include "packetforge/cli.hpp"
#include "packetforge/analysis.hpp"
#include "packetforge/reporting.hpp"
#include "rules.hpp"
#include <charconv>
#include <cmath>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
namespace packetforge {
namespace {
std::uint64_t number(const std::string& text) {
    std::uint64_t value=0; const auto parsed=std::from_chars(text.data(),text.data()+text.size(),value);
    if (parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || value==0 || value>1000000000)
        throw std::runtime_error("expected positive integer <= 1000000000: "+text);
    return value;
}
double duration(const std::string& text) {
    double value=0; const auto parsed=std::from_chars(text.data(),text.data()+text.size(),value);
    if (parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || !std::isfinite(value) || value<=0 || value>86400)
        throw std::runtime_error("duration must be a number in (0, 86400] seconds");
    return value;
}
void help() {
    std::cout << "PacketForge | Network Packet Analyzer & Intrusion Detection System\n"
        "Author: Mayank Kumar Karn\n\n"
        "Usage:\n  packetforge interfaces\n"
        "  packetforge capture --interface NAME [--count N] [--duration SECONDS]\n"
        "  packetforge analyze --pcap FILE [--count N]\n\n"
        "Analysis options:\n"
        "  --ids / --no-ids       Enable (default) or disable metadata detection\n"
        "  --rules FILE           Validated JSON overrides for rules, limits and policy\n"
        "  --policy               Print Firewall Policy Simulation decisions\n"
        "  --verbose              Packet metadata for each observed frame\n"
        "  --quiet                Suppress immediate alerts; retain final summary/reports\n"
        "  --report FORMAT        json, csv, html, or all\n"
        "  --output PREFIX        Report path prefix (existing files are never overwritten)\n"
        "Capture-only options:\n"
        "  --promiscuous          Explicitly request socket-scoped promiscuous membership\n"
        "  --duration SECONDS     Positive duration, up to 86400 seconds\n"
        "  --help                 Show this help\n\n"
        "Offline analysis supports classic Ethernet PCAP without root or internet.\n"
        "Live AF_PACKET capture needs CAP_NET_RAW on an authorized Linux interface.\n"
        "PacketForge observes metadata; it never blocks, forwards or injects packets.\n"
        "Compatibility: sniffer --interface NAME; forwarder --interface NAME (simulation).\n";
}
}
int run_cli(int argc,char** argv,bool legacy,bool policy) {
    try {
        if (argc<2) { help(); return legacy ? 2 : 0; }
        if (std::string(argv[1])=="--help") { if (argc!=2) throw std::runtime_error("--help takes no arguments"); help(); return 0; }
        const std::string command=legacy ? "capture" : argv[1];
        std::string path,rules_path,report_format,output;
        CaptureOptions options; bool verbose=false,ids=true,quiet=false;
        std::set<std::string> seen;
        for (int i=legacy ? 1 : 2;i<argc;++i) {
            const std::string arg=argv[i];
            if (!seen.insert(arg).second) throw std::runtime_error("duplicate option: "+arg);
            auto value=[&]() { if (++i>=argc) throw std::runtime_error("missing value for "+arg); return std::string(argv[i]); };
            if (arg=="--interface") options.interface=value();
            else if (arg=="--pcap") path=value();
            else if (arg=="--count") options.count=number(value());
            else if (arg=="--duration") options.duration=duration(value());
            else if (arg=="--promiscuous") options.promiscuous=true;
            else if (arg=="--verbose") verbose=true;
            else if (arg=="--quiet") quiet=true;
            else if (arg=="--ids") ids=true;
            else if (arg=="--no-ids") ids=false;
            else if (arg=="--policy") policy=true;
            else if (arg=="--rules") rules_path=value();
            else if (arg=="--report") report_format=value();
            else if (arg=="--output") output=value();
            else if (arg=="--help" && argc==(legacy ? 2 : 3)) { help(); return 0; }
            else throw std::runtime_error("unknown option: "+arg);
        }
        if (command=="interfaces") {
            if (argc!=2) throw std::runtime_error("interfaces takes no options");
            list_interfaces(); return 0;
        }
        if (command!="capture" && command!="analyze") throw std::runtime_error("unknown command: "+command);
        if (command=="capture" && (options.interface.empty() || seen.count("--pcap"))) throw std::runtime_error("capture requires --interface and does not accept --pcap");
        if (command=="analyze" && (path.empty() || seen.count("--interface") || seen.count("--duration") || options.promiscuous))
            throw std::runtime_error("analyze requires --pcap; capture-only options are invalid");
        if (seen.count("--ids") && seen.count("--no-ids")) throw std::runtime_error("--ids and --no-ids conflict");
        if (!report_format.empty() && report_format!="json" && report_format!="csv" && report_format!="html" && report_format!="all")
            throw std::runtime_error("--report must be json, csv, html or all");
        if (seen.count("--report") && report_format.empty()) throw std::runtime_error("empty report format");
        if (seen.count("--output") && (report_format.empty() || output.empty())) throw std::runtime_error("--output requires a nonempty prefix and --report");
        if (seen.count("--rules") && rules_path.empty()) throw std::runtime_error("empty rules path");
        const auto config=rules_path.empty() ? Config::defaults() : Config::load(rules_path);
        Analysis analysis(config,ids);
        const auto source=command=="capture" ? options.interface : path;
        std::cout << "PacketForge | " << command << " | " << source << " | IDS " << (ids ? "enabled" : "disabled") << '\n';
        if (command=="capture") std::cout << "Capture: " << (options.promiscuous ? "promiscuous" : "non-promiscuous") << "; Ctrl+C stops gracefully\n";
        if (policy) std::cout << "Firewall Policy Simulation: no traffic is blocked or forwarded\n";
        auto emit=[&](const Json& alert) {
            if (!quiet) std::cout << '[' << alert.at("severity").get<std::string>() << "] " << alert.at("rule_id").get<std::string>() << " | "
                << alert.at("timestamp").get<std::string>() << " | " << alert.at("source").get<std::string>() << " -> "
                << alert.at("destination").get<std::string>() << " | observed=" << alert.at("observed_count") << " threshold="
                << alert.at("threshold") << " window=" << alert.at("detection_window_seconds") << "s\n";
        };
        auto consume=[&](const Packet& p) {
            analysis.observe(p,emit);
            if (verbose) {
                std::cout << iso_time(p.timestamp) << ' ' << p.protocol_name() << " [" << p.source << "]:" << p.source_port
                    << " -> [" << p.destination << "]:" << p.destination_port << " cap=" << p.captured_length << " wire=" << p.wire_length
                    << " status=" << status_name(p.status);
                if (p.ethernet) std::cout << " mac=" << p.source_mac << "->" << p.destination_mac << " ethertype=" << p.ethertype;
                for (auto vlan:p.vlan_ids) std::cout << " vlan=" << vlan;
                if (p.ipv4 || p.ipv6) std::cout << " ttl/hop=" << unsigned(p.ttl) << " protocol=" << unsigned(p.protocol);
                if (p.fragmented) std::cout << " fragment_offset=" << p.fragment_offset << " more_fragments=" << p.more_fragments;
                if (p.arp) std::cout << " arp_opcode=" << p.arp_opcode << " sender_hw=" << p.arp_sender_hardware << " target_hw=" << p.arp_target_hardware;
                if (p.transport && (p.protocol==1 || p.protocol==58)) std::cout << " type=" << unsigned(p.icmp_type) << " code=" << unsigned(p.icmp_code);
                if (p.protocol==6 && p.transport) std::cout << " flags=" << unsigned(p.tcp_flags) << " seq=" << p.sequence << " ack=" << p.acknowledgment;
                if (!p.detail.empty()) std::cout << " (" << p.detail << ')';
                std::cout << '\n';
            }
            if (policy && p.status==ParseStatus::ok && !p.source.empty()) std::cout << "Source: " << p.source << " | Destination: [" << p.destination << "]:"
                << p.destination_port << " | Policy: " << evaluate_policy(p,config.policy) << '\n';
        };
        auto tick=[&]() {
            const auto now=std::max(now_timestamp(),analysis.statistics.last); analysis.flows.expire(now); analysis.detection.expire(now);
            if (!quiet) std::cout << "[capture] packets=" << analysis.statistics.packets << " bytes=" << analysis.statistics.observed_bytes
                << " active_flows=" << analysis.flows.active_count() << " alerts=" << analysis.total_alerts << std::endl;
        };
        const auto result=command=="capture" ? capture_live(options,consume,tick) : analyze_pcap(path,consume,options.count);
        if (command=="capture") analysis.flows.expire(std::max(now_timestamp(),analysis.statistics.last),true);
        analysis.summary(std::cout);
        if (command=="capture") std::cout << "Kernel capture drops: " << result.kernel_drops << " | Interrupted: " << (result.interrupted ? "yes" : "no") << '\n';
        if (!report_format.empty()) {
            if (output.empty()) output="reports/packetforge-"+std::to_string(now_timestamp());
            for (const auto& report:write_reports(analysis.report(command,source,result),report_format,output)) std::cout << "Report: " << report << '\n';
        }
        return 0;
    } catch (const std::exception& error) { std::cerr << "PacketForge error: " << error.what() << '\n'; return 2; }
}
}
