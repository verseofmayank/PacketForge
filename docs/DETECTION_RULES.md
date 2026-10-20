# PacketForge detection rules

PacketForge uses transparent metadata thresholds, not a trained anomaly model,
malware signature database or attack-confirmation engine. IDS is enabled by default.
Use `--no-ids` to disable it. Every alert includes the exact observed count,
threshold, window, packet-derived evidence and a limitation statement.

## Demonstration defaults

| Rule ID | Grouping and count | Threshold / window | Cooldown | Severity |
| --- | --- | --- | --- | --- |
| `POSSIBLE_TCP_PORT_SCAN` | Source + destination; distinct TCP SYN destination ports | 12 / 10 s | 30 s | MEDIUM |
| `HIGH_TCP_SYN_RATE` | Source + destination; TCP SYN initiation packets | 100 / 10 s | 30 s | MEDIUM |
| `HIGH_ICMP_ECHO_RATE` | Source + destination; ICMPv4/v6 echo requests | 50 / 10 s | 30 s | LOW |
| `SENSITIVE_SERVICE_TRAFFIC` | Source + destination + protocol + service port; observed TCP/UDP packets | 1 / 10 s | 60 s | INFO |
| `CONNECTION_CONCENTRATION` | Source; distinct attempted connections across observed destinations | 40 / 10 s | 30 s | LOW |

The sensitive ports are 22 (commonly SSH), 23 (Telnet), 445 (SMB) and 3389 (RDP).
Either source or destination service port can match; if both match, the destination
port determines the observation key. A port number is not proof of application
identity. Access to a sensitive service is not automatically malicious.

Severity describes the rule's investigation priority, not probability of compromise.
MEDIUM defaults indicate patterns worth validating; LOW allows common operational
explanations; INFO records access observations. HIGH is available for a carefully
tuned local rule but no demonstration rule assigns it by default.

## Window and alert semantics

A window is `(t - window_seconds, t]`. At time t, observations exactly on the left
boundary expire. Counts trigger at **greater than or equal to** the threshold.
Timestamps come from the PCAP when offline, so fast or slow replay has the same
result. Equal timestamps are accepted. Backwards timestamps are rejected.

The first threshold crossing emits an alert. During cooldown, additional qualifying
observations update evidence/counters but do not emit another alert. Once cooldown
expires, an ongoing qualifying pattern can emit again on the next matching packet.
Cooldown zero means one alert per above-threshold episode, rearmed after the
observed count falls below threshold or the window fully expires. No background
alert is emitted without a packet. Expiry retains a key until its cooldown is
no longer needed. Global per-rule state caps can omit evidence and cause missed
detections; counters explicitly show this.

Only supported, successfully decoded, unfragmented transport metadata reaches
rules. Non-initial and initial fragments are excluded from IDS. A syntactically
valid frame with unverified checksums can still contribute; checksum validation
is outside the implementation.

## A. Possible TCP SYN port scan

A candidate has SYN set and ACK, FIN and RST clear. Record destination ports in the
source/destination window. Repeated attempts to one port do not increase the
number of distinct ports. A single connection can never trigger the default rule,
and a configured threshold below two is rejected.

Example: `samples/portscan.pcap` contains 13 SYNs toward ports 1000–1012. The first
alert occurs on port 1011: 12 distinct destination ports in the 10-second window.
The evidence includes the distinct count, packet count and a sorted sample of up
to 32 ports. [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
provides context for service discovery, not proof that the observed source is an adversary.

False positives: vulnerability scanners, inventory tools, authorized testing and
NAT aggregation. Limitations: slow scans outside the window, ACK/FIN scans,
distributed scans and missing capture paths can evade this rule.

## B. Elevated TCP SYN rate

Count every matching SYN initiation packet in the source/destination window,
including retransmissions and capture duplicates. `samples/synrate.pcap` contains
101 copies of one attempt within five seconds. It raises one `HIGH_TCP_SYN_RATE`
alert at count 100; it does not raise connection concentration or a port-scan alert.

This is a burst/rate heuristic, not evidence of server resource exhaustion or a
confirmed SYN flood. Busy clients, unreachable services and duplicate loopback
observations can explain high counts. PacketForge does not calculate handshake
completion ratios or server SYN backlog occupancy.

## C. Elevated ICMP echo activity

Count only echo requests (IPv4 type 8/code 0, IPv6 type 128/code 0). Replies and
other ICMP messages do not count. `samples/icmp_rate.pcap` triggers at request 50.
Monitoring, diagnostics and reachability checks can produce the same behavior.
Packet count alone cannot establish malicious intent or denial of service.

## D. Sensitive service observation

Match either TCP/UDP service port against the configured set and count packets
per directional endpoint/protocol/service key. The default threshold emits an
informational observation on the first packet, then applies a 60-second cooldown.
A reverse-direction reply is a different observation key and may emit separately.
No service banner, authentication attempt, credential or payload is inspected.

## E. Connection concentration

For SYN initiations, count distinct tuples
`(destination IP, source port, destination port, TCP sequence number)` per source.
An identical retransmission does not become a new attempt. Changing initial
sequence numbers or ports may represent a new attempt, but this remains an
approximation without a TCP state machine. Multiple destination hosts can contribute.

When an enabled, nonexcluded port-scan rule would recognize a destination's port
diversity within the concentration rule's evidence window, the concentration
observation is suppressed and `scan_overlap_suppressed` increments. This avoids
reporting the same scan-shaped evidence under two rule names at the default
thresholds. The rules retain separate windows; custom windows can suppress
concentration even if the shorter scan window does not currently trigger. An
already-issued observation is not retroactively withdrawn if traffic later evolves
into a scan. Choose aligned windows when comparing these rules.

`samples/concentration.pcap` uses 41 distinct source ports toward one destination
service. It triggers concentration at 40 attempts, without the SYN-rate or
port-scan rule. Load balancers, proxy servers and application connection churn are
plausible benign explanations.

## Configuration

```bash
./build/packetforge analyze --pcap samples/portscan.pcap --rules config/rules.json
```

A custom JSON file can override only the settings you need; omitted settings retain
built-in defaults. The complete default file is included in `config/rules.json`.

```json
{
  "rules": {
    "POSSIBLE_TCP_PORT_SCAN": {
      "enabled": true,
      "threshold": 20,
      "window_seconds": 15,
      "cooldown_seconds": 60,
      "severity": "MEDIUM",
      "exclude_sources": ["192.0.2.99"],
      "exclude_destinations": []
    },
    "SENSITIVE_SERVICE_TRAFFIC": {
      "ports": [22, 445, 3389],
      "severity": "INFO"
    }
  }
}
```

Exclusions accept exact IPv4/IPv6 literals only; IPv6 text is canonicalized.
CIDR, DNS names, regexes and wildcards in exclusions are unsupported. Policy address
fields separately accept the literal `any`. Unknown keys and rule IDs, duplicate
JSON keys, wrong types, negative counts, invalid severity, invalid IPs and excessive
nesting/file size are rejected. JSON comments are unsupported.

Validation limits: configuration <= 1 MiB, nesting <= 32, thresholds 1–10000
(scan >= 2), windows 1–3600 s, cooldown 0–86400 s, sensitive port list 1–1024
entries in 1–65535. Thresholds cannot exceed the per-rule event budget. Resource
settings have explicit upper/lower bounds; see the loader for their exact ranges.

## Alert schema

Each object contains `alert_id`, `rule_id`, `title`, ISO UTC and nanosecond timestamps,
severity, source/destination and triggering ports, `detection_window_seconds`,
`observed_count`, `threshold`, structured `evidence`, `confidence`, `limitations`,
`recommendation` and nullable `mitre_technique`. IDs increase within one run, not
across a global alert database. For concentration spanning several destinations,
the destination text says so, and evidence includes the destination count; trigger
ports belong to the triggering packet. Reports also include the effective rules.

Per-rule counters expose matched packets, emitted alerts, cooldown suppression,
scan-overlap suppression, dropped keys/events and retained state. Total alert
counts continue beyond the retained-report alert cap. Nothing is labeled a confirmed
compromise. Investigators should correlate with approved activity and endpoint logs.

## Firewall Policy Simulation

The `policy` array is ordered, first match wins, with source/destination addresses,
`destination_port` (-1 means any), and `WOULD_ALLOW` or `WOULD_BLOCK`. If no rule
matches, the result is `WOULD_ALLOW`. Port-specific rules require decoded TCP/UDP
ports. The original demonstration defaults would block destination ports 22/445.
This evaluation only prints observations; the operating system's traffic path is
unaffected. No forwarding, routing, iptables, nftables or NFQUEUE enforcement exists.

## Practical tuning

Start with representative authorized benign captures, check rates by workload,
then measure alert volume on known tests. Raise thresholds or narrow scope for
busy infrastructure; use exclusions sparingly because they create blind spots.
Keep an auditable copy of the effective config with each report. Test threshold
boundaries and time-window expiry after a rule change. Lowering thresholds may
improve sensitivity at the cost of more false positives. Raising them may miss
slow, distributed or low-volume activity. No universal default is defensible.
