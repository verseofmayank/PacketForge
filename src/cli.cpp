#include "packetforge/cli.hpp"
#include "packetforge/capture.hpp"
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string>
namespace packetforge {
namespace {
std::uint64_t number(const std::string& text) {
    std::uint64_t value = 0; const auto parsed = std::from_chars(text.data(), text.data()+text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size() || value == 0 || value > 1000000000)
        throw std::runtime_error("expected positive integer <= 1000000000: " + text);
    return value;
}
void help() {
    std::cout << "PacketForge | passive network packet analyzer\n"
        "Usage: packetforge interfaces\n"
        "       packetforge capture --interface NAME [--count N] [--duration SECONDS] [--promiscuous] [--verbose]\n"
        "       packetforge analyze --pcap FILE [--count N] [--verbose]\n"
        "       packetforge --help\n"
        "Offline analysis needs no privileges. Live capture requires CAP_NET_RAW.\n";
}
}
int run_cli(int argc, char** argv, bool legacy, bool policy) {
    try {
        if (argc < 2) { help(); return legacy ? 2 : 0; }
        if (std::string(argv[1]) == "--help") { help(); return 0; }
        std::string command = legacy ? "capture" : argv[1], path;
        CaptureOptions options; bool verbose = false;
        for (int i = legacy ? 1 : 2; i < argc; ++i) {
            const std::string arg = argv[i];
            auto value = [&]() { if (++i >= argc) throw std::runtime_error("missing value for " + arg); return std::string(argv[i]); };
            if (arg == "--interface") options.interface = value();
            else if (arg == "--pcap") path = value();
            else if (arg == "--count") options.count = number(value());
            else if (arg == "--duration") options.duration = static_cast<double>(number(value()));
            else if (arg == "--promiscuous") options.promiscuous = true;
            else if (arg == "--verbose") verbose = true;
            else throw std::runtime_error("unknown option: " + arg);
        }
        if (command == "interfaces") {
            if (argc != 2) throw std::runtime_error("interfaces takes no options");
            list_interfaces(); return 0;
        }
        if (command != "capture" && command != "analyze") throw std::runtime_error("unknown command: " + command);
        if (command == "capture" && (options.interface.empty() || !path.empty())) throw std::runtime_error("capture requires --interface and does not accept --pcap");
        if (command == "analyze" && (path.empty() || !options.interface.empty() || options.duration || options.promiscuous))
            throw std::runtime_error("analyze requires --pcap; capture-only options are invalid");
        std::cout << "PacketForge | " << command << " | " << (command == "capture" ? options.interface : path) << '\n';
        if (policy) std::cout << "Firewall Policy Simulation: no traffic is blocked or forwarded\n";
        std::uint64_t packets = 0, bytes = 0;
        auto consume = [&](const Packet& p) {
            ++packets; bytes += p.captured_length;
            if (verbose) std::cout << iso_time(p.timestamp) << ' ' << p.protocol_name() << ' ' << p.source << ':'
                << p.source_port << " -> " << p.destination << ':' << p.destination_port << ' ' << status_name(p.status) << '\n';
            if (policy && p.transport) std::cout << "Source: " << p.source << " | Destination: " << p.destination << ':'
                << p.destination_port << " | Policy: " << ((p.destination_port == 22 || p.destination_port == 445) ? "WOULD_BLOCK" : "WOULD_ALLOW") << '\n';
        };
        if (command == "capture") capture_live(options, consume); else analyze_pcap(path, consume, options.count);
        std::cout << "Packets: " << packets << " | Observed bytes: " << bytes << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "PacketForge error: " << e.what() << '\n'; return 2; }
}
}
