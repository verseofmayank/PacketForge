#!/usr/bin/env python3
import subprocess
import sys
binary = sys.argv[1]
for args, expected in [(['--help'], 0), (['interfaces'], 0), (['analyze'], 2),
                       (['analyze', '--pcap', 'missing.pcap'], 2),
                       (['capture', '--count', '-1'], 2), (['wat'], 2)]:
    result = subprocess.run([binary] + args, capture_output=True, text=True)
    assert result.returncode == expected, (args, result.stdout, result.stderr)
from pathlib import Path
root = Path(sys.argv[2])
result = subprocess.run([binary, 'analyze', '--pcap', str(root/'samples/demo.pcap')], capture_output=True, text=True)
assert result.returncode == 0 and 'Packets: 9' in result.stdout, (result.stdout, result.stderr)
print('CLI and offline PCAP checks passed')
