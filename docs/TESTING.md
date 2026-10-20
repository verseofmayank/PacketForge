# PacketForge testing and verification

## Ordinary development checks

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/packetforge_tests
python3 tests/integration.py ./build/packetforge .
```

CTest has three named tests: `unit`, `interfaces` (label `host`) and `integration`.
The first contains many individual assertions; the integration test launches the
CLI repeatedly and validates outputs. A CTest test count is not the same as an
assertion count. The interface test needs ordinary Linux network-interface access,
which some execution sandboxes deny. In those runners, the entirely offline suite is:

```bash
ctest --test-dir build -LE host --output-on-failure
```

A repeatable clean-build runner records actual compiler/test output:

```bash
python3 scripts/verify.py --build-dir build-verify
```

It overwrites its own development log in `docs/evidence/build-and-tests.txt`, not
investigation reports. Build logs are evidence of the recorded environment, not
a claim that every distribution/compiler combination has been tested.

## What is tested

`tests/unit.cpp` covers Ethernet and MAC addresses, single/double VLAN tags and tag
limits, variable IPv4 IHL, IPv6 and extension/fragment metadata, TCP flags/offsets,
UDP length validation, ARP address layouts, ICMPv4/v6 echoes, network byte order,
every truncated prefix of a valid TCP frame, IP/transport boundary contradictions,
IPv4 fragments, unsupported protocols and empty buffers. A deterministic seeded
loop exercises 10,000 random byte buffers under the same parser. This is a smoke
fuzz test, not an exhaustive fuzz campaign or formal verification.

State tests cover directional grouping, counters/duration, idle expiry, active and
archive caps, unique-count saturation, threshold boundaries, repeated-port/attempt
deduplication, window expiry, cooldowns, zero-cooldown episodes, rule exclusions,
SYN/ICMP rules, concentration, scan overlap, state-budget loss, timestamp rejection,
maximum timestamp arithmetic, simulation and serializer escaping.

`tests/integration.py` analyzes every ordinary fixture against expected counts and
classifications, checks benign cases, complete alert fields, CSV parsing, JSON
round trips, HTML escaping/CSP, file overwrite refusal, disabled rules, literal-IP
exclusions, malformed JSON, duplicate/unknown keys, wrong types, invalid numeric
bounds, unsupported PCAPNG/link types, corrupt files, timestamp ordering/precision,
byte order, empty captures and CLI argument validation. It runs as an ordinary user
and uses temporary output directories. No internet or real capture is involved.

## Sanitizers

```bash
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug -DPACKETFORGE_SANITIZERS=ON
cmake --build build-sanitize -j2
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-sanitize --output-on-failure
```

ASan instruments address accesses; UBSan detects selected undefined operations.
Keep `UBSAN_OPTIONS=halt_on_error=1` so an undefined-behavior finding fails the run.
Never run a capability-granted or privileged sanitizer binary as the normal testing
workflow. Offline tests need neither root nor CAP_NET_RAW.

The restricted development runner uses process tracing, which prevents LeakSanitizer
from inspecting threads. In that runner, the executed supported command was:

```bash
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  python3 scripts/verify.py --build-dir /tmp/packetforge-sanitize --sanitize
```

This still enables AddressSanitizer and UndefinedBehaviorSanitizer, but **does not
perform leak checking**. The original `detect_leaks=1` sandbox run failed with:

```text
LeakSanitizer has encountered a fatal error.
LeakSanitizer does not work under ptrace (strace, gdb, etc)
```

Host verification results, if performed after that, are recorded separately below.
No tool/environment failure is counted as a passing test.

## Isolated live-capture tests

The opt-in live test creates a private user and network namespace. It sends a few
ordinary UDP datagrams only to its own loopback receiver and creates a temporary
veth pair inside that namespace. It does not scan another host, inject raw packets,
change the host firewall or inspect unrelated traffic. Namespace destruction removes
its devices. It needs Linux unprivileged user namespaces and `iproute2`:

```bash
unshare --user --map-root-user --net \
  env PACKETFORGE_ISOLATED_TEST=1 python3 tests/live_capture.py build/packetforge
```

Checks include real AF_PACKET UDP capture, a four-packet count limit, captured/wire
lengths, idle duration exit, graceful SIGINT, JSON metadata, interface listing,
Ethernet device binding and explicit promiscuous socket membership. This validates
live Linux behavior in WSL2; it is not a test of every physical NIC, VLAN offload
implementation or access to Windows host traffic. Some distributions disable user
namespaces; there, use an authorized native Linux VM with appropriate capabilities.
The ordinary WSL host's password-requiring sudo was not used.

## HTML verification

The generated `reports/investigation.html` was opened with headless Chromium using
a local `file:` URL. Its screenshot is `docs/evidence/report-preview.png`. The
image was visually inspected for readable layout, counters and protocol/top-talker
sections. Integration tests check escaping, no scripts, CSP and required report
content. This is a Chromium rendering check, not a cross-browser accessibility audit.

## Recorded results

Final local results and raw command output are kept in `docs/evidence/`:

- `build-and-tests.txt`: clean Release build and offline CTest/integration output.
- `sanitizers.txt`: clean ASan/UBSan build and offline results; restricted-runner leak
  checking disabled as explained above.
- `report-preview.png`: actual rendered report screenshot.
- Additional host/live/demo logs are recorded when the final delivery checks run.

The GitHub Actions workflow adds standard and sanitizer builds on Ubuntu and checks
fixture regeneration. A workflow file is not proof that remote CI passed; consult
the actual workflow run associated with the delivered branch.

### Final local delivery run (2026-10-21)

Clean GCC 15.2.0 Release build: passed without compiler warnings. Host CTest:
**3/3 passed** (`unit`, `interfaces`, `integration`). Unit binary: **10,153 checks**,
including 10,000 randomized inputs. Integration driver: **68 subprocess checks**
plus serialization/configuration/fixture assertions. Clean Debug ASan/UBSan build:
**2/2 offline CTest targets passed**, with `ASAN_OPTIONS=detect_leaks=0` and
`UBSAN_OPTIONS=halt_on_error=1`; separate direct unit/integration invocations passed.

The isolated WSL2 live test passed: four real UDP frame observations, 288 captured
and wire bytes, zero malformed/truncated frames, zero kernel drops, and one
transport flow. Count, duration, SIGINT, Ethernet binding and opt-in promiscuous
checks all succeeded. Loopback can supply both outgoing and incoming copies;
four observations do not imply four distinct UDP transmissions.

The report screenshot was generated by Chromium (1440 × 1300) from the actual
mixed-protocol HTML report and visually inspected. The normal demo has 9 packets
and no IDS alerts. Port-scan and SYN-rate fixtures emit one expected alert each.
