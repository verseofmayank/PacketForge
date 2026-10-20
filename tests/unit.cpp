#include "packetforge/packet.hpp"
#include "packetforge/analysis.hpp"
#include "packetforge/reporting.hpp"
#include "rules.hpp"
#include <random>
#include <limits>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace packetforge;
namespace {
unsigned checks = 0;
void check(bool condition, const char* message) { ++checks; if (!condition) throw std::runtime_error(message); }
void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t value) { b[o] = static_cast<std::uint8_t>(value >> 8); b[o+1] = static_cast<std::uint8_t>(value); }
std::vector<std::uint8_t> tcp() {
    std::vector<std::uint8_t> b(54); put16(b,12,0x0800); b[14]=0x45; put16(b,16,40); b[22]=64; b[23]=6;
    b[26]=192; b[28]=2; b[29]=1; b[30]=198; b[31]=51; b[32]=100; b[33]=2;
    put16(b,34,12345); put16(b,36,443); b[38]=0x12; b[39]=0x34; b[40]=0x56; b[41]=0x78;
    b[46]=0x50; b[47]=2; put16(b,48,4096); return b;
}
Packet parse(const std::vector<std::uint8_t>& b) { return parse_packet(b.data(), b.size(), static_cast<std::uint32_t>(b.size()), 0); }
void parser_tests() {
    auto b=tcp(); auto p=parse(b);
    check(p.status==ParseStatus::ok && p.ethernet && p.ipv4 && p.transport, "Ethernet IPv4 TCP");
    check(p.source=="192.0.2.1" && p.destination=="198.51.100.2", "addresses");
    check(p.source_port==12345 && p.destination_port==443 && p.sequence==0x12345678 && p.tcp_window==4096, "network order");
    check(p.syn_attempt() && p.tcp_header_length==20 && p.ttl==64, "TCP fields");
    for (std::size_t n=0; n<b.size(); ++n) check(parse_packet(b.data(),n,54,0).status==ParseStatus::truncated, "truncated prefix");
    b[14]=0x44; check(parse(b).status==ParseStatus::malformed,"IHL minimum"); b=tcp();
    b[46]=0x40; check(parse(b).status==ParseStatus::malformed,"TCP offset minimum"); b=tcp();
    put16(b,16,20); check(parse(b).status==ParseStatus::malformed,"Ethernet padding cannot supply TCP header"); b=tcp();
    put16(b,20,1); p=parse(b); check(p.fragmented && p.fragment_offset==8 && !p.transport,"non-initial IPv4 fragment");
    b=tcp(); b.insert(b.begin()+34,4,0); b[14]=0x46; put16(b,16,44); check(parse(b).destination_port==443,"IPv4 options");
    b=tcp(); b.insert(b.begin()+12,{0x81,0,0,42}); p=parse(b); check(p.vlan_ids.size()==1 && p.vlan_ids[0]==42 && p.destination_port==443,"VLAN");
    b=tcp(); b[23]=99; check(parse(b).status==ParseStatus::unsupported,"unsupported protocol");
    check(parse_packet(nullptr,0,0,0).status==ParseStatus::truncated,"empty buffer");
}
void protocol_tests() {
    auto b=tcp(); b[47]=0x3f; auto p=parse(b);
    check(p.tcp_flags==0x3f && !p.syn_attempt(),"TCP flags including FIN/SYN/RST/PSH/ACK/URG");
    b[47]=0x12; check(!parse(b).syn_attempt(),"SYN ACK not initiation");
    b=tcp(); b.insert(b.begin()+12,{0x88,0xa8,0,1,0x81,0,0,2}); p=parse(b);
    check(p.vlan_ids==std::vector<std::uint16_t>({1,2}) && p.destination_port==443,"double VLAN");
    b.insert(b.begin()+12,{0x81,0,0,3}); check(parse(b).status==ParseStatus::unsupported,"VLAN depth limit");
    b=tcp(); b.resize(42); b[23]=17; put16(b,16,28); put16(b,38,8); p=parse(b);
    check(p.transport && p.udp_length==8 && p.destination_port==443,"UDP decode");
    put16(b,38,7); check(parse(b).status==ParseStatus::malformed,"UDP short length");
    put16(b,38,9); check(parse(b).status==ParseStatus::malformed,"UDP long length");
    b=tcp(); b.resize(42); b[23]=1; put16(b,16,28); b[34]=8; b[35]=0; p=parse(b);
    check(p.echo_request && p.icmp_code==0 && p.transport,"ICMP request");
    b[34]=0; check(parse(b).echo_reply,"ICMP reply");
    b[35]=1; check(!parse(b).echo_reply,"ICMP echo code validation");
    b.assign(42,0); put16(b,12,0x0806); put16(b,14,1); put16(b,16,0x0800); b[18]=6; b[19]=4;
    put16(b,20,1); b[22]=2; b[28]=192; b[30]=2; b[31]=10; b[38]=192; b[40]=2; b[41]=20; p=parse(b);
    check(p.arp && p.arp_opcode==1 && p.source=="192.0.2.10" && p.destination=="192.0.2.20","ARP fields");
    check(p.arp_sender_hardware=="02:00:00:00:00:00" && p.arp_target_hardware=="00:00:00:00:00:00","ARP MACs");
    b[19]=16; check(parse(b).status==ParseStatus::truncated,"ARP variable length bounds");
    b.assign(62,0); put16(b,12,0x86dd); b[14]=0x60; put16(b,18,8); b[20]=58; b[21]=64;
    b[22]=0x20;b[23]=1;b[24]=0x0d;b[25]=0xb8;b[37]=1;
    b[38]=0x20;b[39]=1;b[40]=0x0d;b[41]=0xb8;b[53]=2;b[54]=128; p=parse(b);
    check(p.ipv6 && p.echo_request && p.source=="2001:db8::1" && p.destination=="2001:db8::2" && p.ttl==64,"IPv6 ICMP");
    auto ipv6=b; b.insert(b.begin()+54,8,0); b[20]=0; b[54]=58; put16(b,18,16); p=parse(b);
    check(p.status==ParseStatus::ok && p.next_header==0 && p.protocol==58 && p.echo_request,"IPv6 hop-by-hop extension");
    b[55]=3; check(parse(b).status==ParseStatus::malformed,"IPv6 extension payload bounds");
    b=ipv6; b.insert(b.begin()+54,8,0); b[20]=44; b[54]=58; put16(b,18,16); put16(b,56,8); p=parse(b);
    check(p.fragmented && p.fragment_offset==8 && !p.transport,"IPv6 noninitial fragment");
    put16(b,56,0); p=parse(b); check(!p.fragmented && p.echo_request,"IPv6 atomic fragment");
    b=ipv6; b[20]=50; check(parse(b).status==ParseStatus::unsupported,"IPv6 ESP explicit unsupported");
    b=ipv6; put16(b,18,0); check(parse(b).status==ParseStatus::unsupported,"jumbogram unsupported");
    b=ipv6; b.resize(54); put16(b,18,0); b[20]=59; check(parse(b).status==ParseStatus::ok,"IPv6 no next header");
    b=tcp(); b.resize(58); put16(b,16,44); put16(b,20,0x2000); p=parse(b);
    check(p.status==ParseStatus::ok && p.fragmented && p.transport,"complete TCP header in initial fragment");
    b=tcp(); put16(b,20,0x2000); check(parse(b).status==ParseStatus::malformed,"non-final fragment alignment");
    b=tcp(); b.resize(42); b[23]=17; put16(b,16,28); put16(b,20,0x2000); put16(b,38,100); p=parse(b);
    check(p.status==ParseStatus::ok && p.fragmented && p.udp_length==100,"fragmented UDP full datagram length");
    b=tcp(); put16(b,16,100); check(parse(b).status==ParseStatus::malformed,"IP total exceeds wire");
    check(parse_packet(b.data(),b.size(),120,0).status==ParseStatus::truncated,"IP total within wire beyond capture");
    b=tcp(); p=parse_packet(b.data(),b.size(),100,0); check(p.capture_truncated && p.transport,"capture truncation distinct from header validity");
    check(parse_packet(b.data(),b.size(),20,0).status==ParseStatus::malformed,"caplen cannot exceed wire length");
    b=tcp(); b[14]=0x65; check(parse(b).status==ParseStatus::malformed,"wrong IPv4 version");
    b=tcp(); put16(b,16,19); check(parse(b).status==ParseStatus::malformed,"IP total below IHL");
    b=tcp(); b[46]=0xf0; check(parse(b).status==ParseStatus::malformed,"TCP options exceed IP payload");
    check(iso_time(1700000000LL*second+123456789)=="2023-11-14T22:13:20.123456789Z","nanosecond timestamp format");
}
Packet syn(Timestamp time=0,std::uint16_t port=443) {
    auto p=parse(tcp());p.timestamp=time;p.destination_port=port;return p;
}
Config only(const std::string& id,std::size_t threshold=3) {
    auto c=Config::defaults();for (auto& [name,rule]:c.rules) rule.enabled=name==id;
    auto& r=c.rules.at(id);r.threshold=threshold;r.window_seconds=10;r.cooldown_seconds=30;return c;
}
void flow_tests() {
    auto c=Config::defaults(); c.max_flows=2;c.max_unique_flows=2;c.flow_timeout_seconds=10;
    FlowTable flows(c);auto p=syn();flows.observe(p);p.timestamp=second;flows.observe(p);
    check(flows.active_count()==1 && flows.unique_count()==1,"flow grouping");
    auto data=flows.json();check(data[0]["packets"]==2 && data[0]["observed_bytes"]==108 && data[0]["duration_seconds"]==1,"flow counters");
    std::swap(p.source,p.destination);std::swap(p.source_port,p.destination_port);flows.observe(p);
    check(flows.active_count()==2 && flows.unique_count()==2,"reverse directional flow");
    p.destination_port=80;flows.observe(p);check(flows.evictions==1 && flows.unique_saturated,"bounded flow eviction and unique saturation");
    flows.expire(11*second,true);check(flows.active_count()==0 && flows.expired==2,"idle expiry boundary");
    check(flows.json().size()==2 && flows.archives_discarded==1,"bounded flow archive");
    p.fragmented=true;flows.observe(p);check(flows.active_count()==0,"fragments not grouped into partial flows");
}
void detection_tests() {
    {
        DetectionEngine engine(only("POSSIBLE_TCP_PORT_SCAN"));
        check(engine.observe(syn(0,80)).empty(),"one SYN is not scan");
        check(engine.observe(syn(second,80)).empty(),"same port deduplicated");
        check(engine.observe(syn(2*second,81)).empty(),"scan below boundary");
        auto a=engine.observe(syn(3*second,82));check(a.size()==1 && a[0]["observed_count"]==3,"scan threshold inclusive");
        check(a[0]["mitre_technique"]=="T1046 - Network Service Discovery","scan MITRE");
        check(engine.observe(syn(4*second,83)).empty(),"scan cooldown");
    }
    {
        DetectionEngine engine(only("POSSIBLE_TCP_PORT_SCAN"));
        engine.observe(syn(0,80));engine.observe(syn(second,81));
        check(engine.observe(syn(10*second,82)).empty(),"half-open sliding window expires exact left edge");
        check(engine.observe(syn(10*second+1,83)).size()==1,"remaining window threshold");
    }
    {
        DetectionEngine engine(only("HIGH_TCP_SYN_RATE"));auto p=syn();p.tcp_flags=0x12;
        check(engine.observe(p).empty(),"SYN ACK excluded");
        check(engine.observe(syn()).empty() && engine.observe(syn(second)).empty(),"SYN below boundary");
        check(engine.observe(syn(2*second)).size()==1,"SYN threshold");
        check(engine.observe(syn(3*second)).empty(),"SYN cooldown");
        engine.observe(syn(31*second));engine.observe(syn(32*second));
        check(engine.observe(syn(33*second)).size()==1,"SYN cooldown expiry and window reset");
    }
    {
        DetectionEngine engine(only("HIGH_ICMP_ECHO_RATE"));auto p=syn();p.protocol=1;p.echo_request=true;p.icmp_type=8;
        engine.observe(p);p.timestamp=second;engine.observe(p);p.timestamp=2*second;
        auto a=engine.observe(p);check(a.size()==1 && a[0]["rule_id"]=="HIGH_ICMP_ECHO_RATE","ICMP threshold");
        p.echo_request=false;p.echo_reply=true;p.timestamp=40*second;check(engine.observe(p).empty(),"echo replies excluded");
    }
    {
        auto c=only("CONNECTION_CONCENTRATION");DetectionEngine engine(c);auto p=syn();
        for (int i=0;i<10;++i) check(engine.observe(p).empty(),"retransmitted attempt deduplication");
        p.source_port++;engine.observe(p);p.destination="198.51.100.21";
        auto a=engine.observe(p);check(a.size()==1 && a[0]["evidence"]["distinct_destinations"]==2,"concentration across destinations");
        c.rules.at("POSSIBLE_TCP_PORT_SCAN").enabled=true;c.rules.at("POSSIBLE_TCP_PORT_SCAN").threshold=2;
        DetectionEngine overlap(c);overlap.observe(syn(0,80));overlap.observe(syn(second,81));a=overlap.observe(syn(2*second,82));
        check(a.empty() && overlap.counters()["CONNECTION_CONCENTRATION"]["scan_overlap_suppressed"]==1,"scan overlap suppressed");
    }
    {
        auto c=only("SENSITIVE_SERVICE_TRAFFIC",1);DetectionEngine engine(c);
        auto p=syn();p.source_port=22;check(engine.observe(p).size()==1,"sensitive source service port");
        check(engine.observe(p).empty(),"sensitive cooldown deduplication");
        c.rules.at("SENSITIVE_SERVICE_TRAFFIC").exclude_sources.insert(p.source);DetectionEngine excluded(c);
        check(excluded.observe(p).empty(),"source exclusion");
    }
    {
        auto c=only("HIGH_TCP_SYN_RATE",2);c.max_rule_keys=1;c.max_rule_events=2;DetectionEngine engine(c);
        engine.observe(syn());auto p=syn();p.source="192.0.2.99";engine.observe(p);
        check(engine.counters()["HIGH_TCP_SYN_RATE"]["dropped_keys"]==1,"bounded keys visible");
        engine.observe(syn());engine.observe(syn());check(engine.counters()["HIGH_TCP_SYN_RATE"]["dropped_events"]==1,"bounded events visible");
        engine.expire(40*second);check(engine.counters()["HIGH_TCP_SYN_RATE"]["retained_keys"]==0,"expired detector storage reclaimed");
    }
    {
        auto c=only("HIGH_TCP_SYN_RATE",2);c.rules.at("HIGH_TCP_SYN_RATE").cooldown_seconds=0;DetectionEngine engine(c);
        engine.observe(syn());check(engine.observe(syn()).size()==1,"zero cooldown crossing");
        check(engine.observe(syn()).empty(),"zero cooldown deduplicates same threshold episode");
        engine.observe(syn(11*second));check(engine.observe(syn(11*second)).size()==1,"zero cooldown rearm after expiry");
    }
    {
        DetectionEngine engine(Config::defaults());auto p=syn();p.fragmented=true;
        check(engine.observe(p).empty(),"fragmented traffic excluded from IDS");
        p.fragmented=false;p.status=ParseStatus::malformed;check(engine.observe(p).empty(),"malformed traffic excluded from IDS");
        auto c=only("HIGH_TCP_SYN_RATE",1);Analysis analysis(c,true);analysis.observe(syn());
        bool threw=false;try { analysis.observe(syn(-1)); } catch (const std::runtime_error&) { threw=true; }
        check(threw,"backwards timestamp rejected");
        FlowTable flows(c);p=syn(std::numeric_limits<Timestamp>::max());flows.observe(p);
        DetectionEngine maximum(c);check(maximum.observe(p).size()==1,"maximum timestamp arithmetic");
    }
}
void report_tests() {
    check(html_escape("<a x=\"'\">&")=="&lt;a x=&quot;&#39;&quot;&gt;&amp;","HTML escaping");
    check(csv_field("a,\"b\"")=="\"a,\"\"b\"\"\"","CSV quoting");
    check(csv_field("=1+1")=="\"'=1+1\"","CSV formula safety");
    auto c=Config::defaults();Analysis analysis(c,true);analysis.observe(syn());
    const auto report=analysis.report("analyze","<test>",CaptureResult{1,0,false});
    check(Json::parse(report.dump())==report,"JSON roundtrip");
    check(html_report(report).find("&lt;test&gt;")!=std::string::npos,"report escapes metadata");
    check(evaluate_policy(syn(0,22),c.policy)=="WOULD_BLOCK" && evaluate_policy(syn(),c.policy)=="WOULD_ALLOW","first-match simulation");
    auto tiny=only("HIGH_TCP_SYN_RATE",1);tiny.max_alerts=1;tiny.rules.at("HIGH_TCP_SYN_RATE").cooldown_seconds=1;
    Analysis bounded(tiny,true);bounded.observe(syn());bounded.observe(syn(2*second));
    check(bounded.alerts.size()==1 && bounded.total_alerts==2 && bounded.alerts_not_retained==1,"bounded alerts retain total counts");
    Statistics stats(1);stats.observe(syn());auto p=syn(second);p.source="192.0.2.99";stats.observe(p);
    check(stats.omitted_sources==1 && stats.json()["packets_per_second"]==2,"bounded talkers and rates");
}
void fuzz_tests() {
    std::mt19937 random(0x5046);
    for (int iteration=0;iteration<10000;++iteration) {
        std::vector<std::uint8_t> bytes(random()%256);
        for (auto& byte:bytes) byte=static_cast<std::uint8_t>(random());
        if (bytes.size()>14 && iteration%2==0) { bytes[12]=8;bytes[13]=0; }
        const auto a=parse_packet(bytes.data(),bytes.size(),static_cast<std::uint32_t>(bytes.size()+random()%100),0);
        check(a.captured_length==bytes.size(),"random parser bounded decode");
    }
}

}
int main() { try { parser_tests(); protocol_tests(); flow_tests(); detection_tests(); report_tests(); fuzz_tests(); std::cout << checks << " checks passed\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; } }
