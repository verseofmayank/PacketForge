# PacketForge interview preparation

Author: Mayank Kumar Karn. These scripts describe implemented behavior. Adapt the
motivation to your real experience and explain only code and results you understand.
The project evolved from the original raw-socket sniffer and policy demonstration
with coding-assistant support; avoid presenting generated work as entirely handwritten.

## 60-second introduction

“PacketForge is my C++17 network packet analyzer and lightweight intrusion detection
project for Linux. I started with raw-socket capture to understand what Ethernet,
IP and transport headers actually contain, then developed a shared analysis pipeline
for both live traffic and offline PCAP files.

“The key engineering focus is safe parsing: every field is bounds-checked, IP options
and VLAN tags are handled, and non-initial fragments never get interpreted as TCP
ports. I track bounded directional flows and detect five metadata patterns using
configurable sliding windows, including possible SYN port scans and elevated SYN
activity. Alerts explain the observed count, threshold, timeframe and limitations.

“I can demonstrate the entire IDS offline with synthetic captures and export JSON,
CSV and HTML reports. The project includes automated boundary tests and sanitizer
checks. It is a passive educational NIDS: its firewall feature simulates decisions
and does not block traffic.”

## Three-minute technical explanation

**First minute — capture and parsing.**

“Live capture creates an AF_PACKET/SOCK_RAW socket and binds it to an explicitly
selected interface. The kernel gives it copies of observed frames. A RAII wrapper
closes the descriptor; poll enforces limits, and the signal handler only sets a
flag. Offline capture uses libpcap and recorded timestamps. Both feed exactly the
same parser and analysis function, which makes the detection demo reproducible.

“I replaced structure casts over untrusted data with bounded byte reads. Ethernet
is normally 14 bytes, but VLAN tags change the IP offset. IPv4 IHL changes its
header size, so assuming 20 bytes is unsafe. IP total length also limits transport
parsing: Ethernet padding must not become a fake TCP header. The parser separates
truncated capture data, internally malformed fields and unsupported protocols.”

**Second minute — state and detection.**

“TCP/UDP flows use a directional five-tuple. Each record counts packets and captured
bytes, first and last observation times and TCP flags. That is metadata grouping,
not TCP stream reconstruction. Idle timeout and capacity eviction bound storage.

“The port-scan rule groups SYN initiations by source and destination, counts distinct
destination ports in a sliding time window, and alerts at the configured threshold.
Repeated SYNs to one port do not count as a multi-port scan. The high-SYN rule counts
packets including retries, while connection concentration deduplicates identical
attempt tuples. ICMP echo activity and sensitive service observations use similar
metadata windows. Cooldowns and scan-overlap suppression reduce redundant alerts.
All state has caps and loss counters, so bounded memory has an explicit detection
tradeoff rather than an invisible claim of completeness.”

**Third minute — evidence, validation and limits.**

“An alert includes UTC timestamps, severity, endpoints, counts, thresholds, evidence,
limitations and a suggested investigation step. Only the possible service-discovery
rule maps to MITRE T1046. I deliberately say ‘possible scan’ or ‘elevated SYN rate’
instead of asserting compromise or denial of service.

“My deterministic captures use reserved addresses, with benign and suspicious
examples. Tests cover parser boundaries, byte order, VLANs, fragmentation, window
expiry, cooldowns, configuration errors and exports. Sanitizers check memory and
undefined behavior. Live tests run in an isolated Linux network namespace.

“JSON supports further analysis; CSV exports alerts and flows; the HTML report
works entirely offline and escapes untrusted values. Current limits include no
IP reassembly, TCP reconstruction, DNS analysis, decryption or high-throughput
claim. The historical ‘forwarder’ is honestly labeled Firewall Policy Simulation:
observing a socket copy cannot enforce a DROP decision on the original traffic.”

## Five-minute terminal demonstration

Prepare a release build and a fresh output prefix before the interview. No root,
network connection, scanner or target machine is needed.

1. **0:00–0:40 — Show scope and normal traffic.**

   ```bash
   ./build/packetforge --help
   ./build/packetforge analyze --pcap samples/demo.pcap
   ```

   Explain nine packets across several layers, no default alerts, and the distinction
   between overlapping protocol counters and total frames.

2. **0:40–1:40 — Show two different TCP behaviors.**

   ```bash
   ./build/packetforge analyze --pcap samples/portscan.pcap --ids
   ./build/packetforge analyze --pcap samples/synrate.pcap
   ```

   Point to 12 distinct ports versus 100 SYN packets. Explain why repeated attempts
   do not become distinct ports and why high SYN activity is not automatically DoS.

3. **1:40–2:30 — Show safe failure and honest policy.**

   ```bash
   ./build/packetforge analyze --pcap samples/malformed.pcap --verbose
   ./build/packetforge analyze --pcap samples/sensitive.pcap --policy
   ```

   Explain truncated versus malformed, and that WOULD_BLOCK changes no traffic.

4. **2:30–3:40 — Show the evidence report.**

   ```bash
   ./build/packetforge analyze --pcap samples/mixed.pcap \
     --rules config/rules.json --report all --output reports/interview-demo
   ```

   Open the local HTML, inspect an alert's evidence, threshold and limitation,
   then show the machine-readable JSON and flow CSV.

5. **3:40–5:00 — Show engineering validation.**

   ```bash
   ctest --test-dir build --output-on-failure
   cat config/rules.json
   ```

   Discuss timestamp-driven windows, state budgets and the testing evidence. If
   interface enumeration is blocked by a restricted runner, use `-LE host` for
   the offline tests and explain the environment difference. Do not claim the
   absence of alerts proves that a capture is safe.

`scripts/demo.sh` runs the analyses with a fresh report directory automatically.

## Twenty realistic technical questions

### 1. What is PacketForge, and what problem does it solve?

It is a passive Linux network analyzer and lightweight network IDS. It turns
captured protocol metadata into flow/statistical summaries and explainable
observations. Its main educational problem is connecting low-level networking,
safe systems programming and defensible detection. It is not a production SOC
platform or a blocking IPS.

### 2. Why did you build it, and why C++ rather than Python?

A defensible motivation is learning Linux capture APIs, byte layout, resource
ownership and stateful metadata detection by building them. C++ provides direct
socket/libpcap integration, explicit types and predictable object lifetime. Python
would be excellent for prototyping and analytics; it is used here only for fixture
and test tooling. C++ is not automatically fast or safe: correctness and profiling
still matter, and unsafe pointer casts were a major problem in the original code.

### 3. Why raw sockets, what is AF_PACKET, and what is CAP_NET_RAW?

AF_PACKET is Linux's link-layer packet socket family. SOCK_RAW includes the link
header; ETH_P_ALL subscribes to all Ethernet protocol types on the selected
interface. CAP_NET_RAW authorizes raw/packet socket creation in the relevant user
namespace. It is narrower than full root privileges but still sensitive. This is
different from AF_INET raw sockets, which operate around the network layer. PacketForge
keeps AF_PACKET for educational value and uses libpcap for portable file parsing.

### 4. How does a packet get from the network into your code?

The NIC/driver passes data into the kernel. A bound packet socket receives observed
frame copies. PacketForge polls the socket, calls recvmsg, records capture/wire
length and a kernel timestamp, then passes a bounded byte view into the parser.
The decoded metadata goes into statistics, flows and IDS. Processing is single-threaded;
there is no guarantee of lossless capture at high load, so kernel drops are reported.

### 5. What is the difference between a frame, packet, segment and datagram?

An Ethernet frame is the link-layer unit with MAC addressing and EtherType. Its
payload may be an IP packet with network-layer addresses. An IP payload may carry
a TCP segment or UDP datagram with transport ports. UDP is message-oriented; TCP
is a byte stream despite arriving in segments. “Packet” is also used loosely for
all these units, but parser offsets require the layer distinction.

### 6. How do Ethernet, IPv4 and IPv6 headers differ?

Ethernet identifies local link endpoints through MAC addresses; switches use those
addresses. IPv4 identifies routed network endpoints, has a variable header through
IHL/options, and carries total length, TTL, protocol and fragmentation fields.
IPv6 has a fixed 40-byte base header plus possible extensions, a payload length,
next-header chain and hop limit. VLAN tags extend the Ethernet header and change
where IP begins. Routers can replace link headers while IP packets move between links.

### 7. What do TCP and UDP headers contribute?

Both identify transport endpoints with ports. TCP also carries sequence and
acknowledgment numbers, a data offset, control flags and receive window, supporting
reliability and ordered delivery in the TCP implementation. UDP has an eight-byte
header with ports, length and checksum and does not itself guarantee delivery,
order or retransmission. PacketForge extracts metadata; it does not implement either
transport protocol or verify their checksums.

### 8. Explain the TCP three-way handshake and SYN, ACK, FIN and RST.

A client sends SYN with initial sequence x. A listening server replies SYN/ACK
with its own initial sequence y and acknowledgment x+1. The client acknowledges
y+1. SYN consumes sequence space. ACK makes the acknowledgment field meaningful.
FIN signals an orderly end to one sending direction and also consumes sequence
space. RST abruptly rejects/resets a connection. PacketForge's initiation rules
count SYN without ACK/FIN/RST; seeing that packet alone does not prove establishment.

### 9. What is the difference between IDS and IPS? Host IDS versus network IDS?

An IDS detects and reports; an IPS is positioned to prevent or block traffic/actions.
A network IDS examines traffic at an observation point; a host IDS examines endpoint
activity such as processes, files and logs. PacketForge is a network metadata IDS.
It sees only what reaches its selected capture point and does not monitor process
or filesystem behavior. Detection alone provides no enforcement authority.

### 10. Signature detection versus anomaly detection: which is this?

Signatures match known patterns, such as an exploit byte sequence or a structured
known-bad indicator. Anomaly detection compares behavior to an expected baseline,
which may be statistical or learned. PacketForge implements rule-based behavioral
threshold heuristics; it is neither a payload signature engine nor a trained anomaly
model. Its thresholds are configured manually and should be tuned against a baseline.

### 11. How exactly do you detect a possible port scan?

Select SYN initiation metadata, group by source/destination, expire events outside
`(now-10s, now]`, and count unique destination ports. The demonstration threshold is
12. A repeated SYN to one service does not increase that count. An alert records
what was observed and applies a per-key cooldown. This detects one narrow scan
pattern and misses many slow, distributed or non-SYN scans. T1046 supplies service-
discovery context rather than attribution.

### 12. How are high SYN rate and connection concentration different?

SYN rate counts packets, including retransmissions. Concentration counts distinct
attempt identities, including destination, ports and initial sequence, across the
source's observed destinations. Thus retries can produce a SYN-rate observation
without concentration. Neither verifies handshake completion. Scan-shaped port
diversity is suppressed for concentration to reduce duplicate explanations.

### 13. How does threshold tuning change false positives and false negatives?

Lower thresholds or longer windows can catch subtler behavior but also legitimate
bursts. Higher thresholds reduce noise but miss lower-rate activity. NAT can merge
many users behind one observed source. Authorized scanning, monitoring and connection
pools need context. Test benign and known suspicious fixtures, then use representative
authorized traffic, explicit exclusions and documented effective configuration.

### 14. Why does returning DROP not block a packet?

AF_PACKET receives a copy for observation; returning an enum only changes local
application control flow. It does not tell the forwarding stack to discard the
original. The original forwarder logged ALLOW/DROP without enforcement. PacketForge
now reports WOULD_ALLOW/WOULD_BLOCK and calls it simulation. Actual enforcement
would require a separate, explicitly designed integration such as a kernel filter
or NFQUEUE, which this project does not implement.

### 15. How do you prevent buffer overreads, and what is network byte order?

Every read verifies offset and required bytes against captured bounds, using
subtraction to avoid offset-addition overflow. IP length narrows the transport
boundary. The parser reads bytes into host-order integers, rather than casting
unaligned network memory to compiler-laid-out structs. Network byte order is big-
endian; for example bytes 0x01 0xbb represent port 443. Header length fields are
validated before advancing. Tests and sanitizers provide evidence, not a formal
proof that all possible bugs are absent.

### 16. How does offline PCAP analysis work, including timestamps?

libpcap reads the global header, link type and packet records. Each record supplies
captured length, original length and timestamp. PacketForge supports classic
Ethernet PCAP, requests nanosecond precision and feeds each record through the same
pipeline as live capture. Windows use recorded time, not the speed of the replay.
Equal times are allowed, decreasing times cause an explicit error. PCAPNG is
rejected even though libpcap can read some PCAPNG files.

### 17. What happens with fragmented IP packets and IPv6 extensions?

IPv4 IHL is variable and fragmentation can separate transport bytes across packets.
A nonzero fragment offset means this is not the start of the transport header, so
ports must not be guessed. Initial fragments are parsed only if a whole header
fits, then excluded from flows/IDS along with all fragments. IPv6 extensions are
walked with bounded lengths and depth; unsupported ESP/jumbograms are explicit.
There is no reassembly or overlapping-fragment evasion defense.

### 18. Why not simply use Wireshark, Snort or Suricata?

For operational investigations and production detection I would use mature tools.
Wireshark offers deep protocol inspection and interactive analysis; Snort/Suricata
provide mature rule ecosystems and production sensor features. PacketForge is small
enough to explain and test end to end. Its value is demonstrating implementation
tradeoffs, memory safety and transparent heuristics, not replacing those tools or
claiming equivalent protocol coverage and performance.

### 19. What are the main limitations, and how would it scale?

There is no application parsing, payload inspection, checksum validation, reassembly,
decryption, distributed correlation or high-speed capture guarantee. Detection
depends on visibility, timestamps, offloads and tuned thresholds. Bounded state
can omit evidence, and top talkers can be incomplete after saturation. To scale,
profile first; consider PACKET_MMAP/ring capture, fewer allocations, incremental
window counters, indexed expiry, flow-affine workers and streaming exports. Preserve
time ordering per key and expose overload counters. Do not promise line-rate
performance without measurements on specified hardware and traffic.

### 20. What did you implement personally, and how can you prove your understanding?

Give an accurate contribution history: the repository began with the raw-socket
sniffer, header structures and first-match rule concept; this revision expanded
those concepts with coding-assistant support. Point to Git commits, the initial
audit and executed tests. Explain one parser boundary, modify a threshold, predict
a fixture's output and run the test. Claim design, review, testing and code work
only to the extent you actually performed and can defend it. Understanding the
implementation is more persuasive than claiming every line was written unaided.

## Implementation challenges to discuss

**Captured length versus protocol length.** A buffer can be long enough overall
while its IP payload is too short for TCP. The decoder now restricts reads to the
validated IP boundary, preventing Ethernet padding from disguising a missing header.
A unit test specifically exercises this.

**VLAN tags and options shift offsets.** Fixed offsets work only on simple packets.
The parser advances through at most two VLAN tags, validates IPv4 IHL, and walks
bounded IPv6 extensions. Tests deliberately insert VLAN and option bytes.

**Fragmented traffic can create fake ports.** Reading transport fields from a later
fragment interprets arbitrary payload as a header. PacketForge explicitly skips
non-initial fragments and excludes all fragments from IDS/flow grouping, trading
coverage for an honest, safe implementation without reassembly.

**Replay time differs from capture time.** Using wall-clock time during PCAP replay
would make alerts depend on CPU speed. Stored timestamps drive windows, exact left-
boundary expiry is tested, and nonchronological files produce a useful error.

**Rule definitions can overlap.** SYN rate measures packets, concentration estimates
new attempts, and port scans measure port diversity. Separate fixtures expose those
differences; concentration deduplicates retransmissions and suppresses scan-shaped
evidence. Explain custom-window limitations rather than claiming perfect correlation.

**Bounded memory changes observability.** Keeping every flow or address forever is
unsafe for long-running capture. Budgets, idle expiry and eviction prevent unbounded
state; saturation counters and lower-bound labels make the loss visible.

**Environment restrictions are different from program failures.** Interface access
and live capabilities can be blocked by a runner. Live behavior was tested in an
isolated WSL Linux user/network namespace with normal local UDP sockets. The ordinary
user's host sudo needs a password; no such password was collected or stored.

**Safe reports still need input validation.** Captured addresses are formatted from
bytes, but filenames/configuration can also contain markup. All HTML dynamic values
are escaped, CSV formula starts are neutralized and files are created exclusively.
The integration suite checks a malicious filename and overwrite refusal.

## Before the interview

Read `packet.cpp`, explain `need()` and the IP boundary, then change one unit test
and predict its result. Read one rule from config through alert creation. Re-run the
offline demo and inspect the JSON evidence. Know which limitations are intentional.
Use `docs/TESTING.md` for exact executed validation and environment caveats; never
quote invented pass counts, performance benchmarks or production deployment claims.
