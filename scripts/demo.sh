#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
binary="${1:-./build/packetforge}"
mkdir -p reports
report_dir=$(mktemp -d reports/demo-XXXXXX)
"$binary" analyze --pcap samples/demo.pcap
"$binary" analyze --pcap samples/portscan.pcap --ids
"$binary" analyze --pcap samples/synrate.pcap
"$binary" analyze --pcap samples/malformed.pcap --verbose
"$binary" analyze --pcap samples/sensitive.pcap --policy
"$binary" analyze --pcap samples/mixed.pcap --rules config/rules.json --report all --output "$report_dir/investigation"
