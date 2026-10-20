# PacketForge repository audit

Audited baseline: `8fd6286f6c3d2e04731b5e49b85b52086ac6f984` on GitHub `main`.
Author: Mayank Kumar Karn. Audit date: 2026-10-21.

The GitHub repository contains six commits. The latest relocates `forwarder.cpp`
and `rules.hpp` into `src/` and `include/`. A separate pre-existing local copy in
`ctf/PacketForge` has an unborn Git branch and untracked files; it was left untouched.
This work continues the GitHub history on `feature/packetforge-analyzer-ids`.

## Baseline verification

Both documented direct compiler builds succeeded with GCC 15.2.0 and
`-std=c++17 -Wall -Wextra`. Original binaries were built in `/tmp`; they were not
run against live traffic during the audit. All six source/documentation files and
`.gitignore` were inspected before editing. No CMake, test suite, configuration
loader, offline reader, reports, or IDS engine exists at baseline.

| Area | Verified finding | Correction plan |
| --- | --- | --- |
| Ethernet | Direct `EthHeader*` buffer cast, no minimum size check; only Ethernet II assumed | Bounded byte decoding and VLAN tags |
| IPv4 | IHL is calculated (not fixed at 20), but version, minimum IHL, total length, capture boundaries and fragments are unchecked | Validate before reading; distinguish wire/captured lengths |
| TCP/UDP | Unchecked structure casts; TCP offset and UDP length ignored | Explicit network-order reads and transport bounds |
| ARP/ICMP | EtherType/protocol detection only; no ARP addresses or ICMP type/code extraction | Decode supported fields |
| IPv6 | Absent | Bounded base/extension parsing with explicit unsupported cases |
| Capture | Real AF_PACKET socket receives frames; no bind, duration/count controls, signal handler or RAII | Explicit interface, limits, passive socket, graceful shutdown |
| Policy | First-match source/destination/port rules are useful educational logic | Preserve simulation using WOULD_ALLOW / WOULD_BLOCK |
| Enforcement | `forwarder.cpp` never forwards, retransmits or drops anything; README calls it a forwarding engine and labels decisions DROP | Correct code/output/docs; no enforcement |
| Rules | Mutable inline hardcoded table; “configurable” means editing/recompiling C++ | Validated external JSON rules and policy |
| Stats | Total and policy-decision counters only; reporting skipped for non-IPv4 | Shared protocol, flow, rate and alert statistics |
| Build/tests | Two manual g++ commands; no automated checks or PCAP workflow | CMake, CTest, synthetic fixtures, sanitizer builds |
| Privacy | No payload display, injection or persistence | Preserve passive metadata-only behavior |

## Preservation

The original implementations remain available at the audited Git commit.
`src/sniffer.cpp` and `src/forwarder.cpp` will become compatibility entry points into
the shared pipeline. `include/headers.hpp` will expose decoded packet types instead
of unsafe on-wire struct layouts. `include/rules.hpp` will preserve first-match
policy evaluation with accurate simulation names. Subsequent implementation and
validation details are recorded in `PROGRESS.md` and `docs/TESTING.md`.
