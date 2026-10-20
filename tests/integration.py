#!/usr/bin/env python3
"""End-to-end offline checks; no root, third-party Python packages or network needed."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
checks = 0

def run(args, code=0):
    global checks
    result = subprocess.run([str(binary)] + list(map(str,args)), capture_output=True, text=True)
    checks += 1
    assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
    return result

run(['--help'])
for args in [['analyze'], ['analyze','--pcap','missing.pcap'], ['capture','--count','-1'], ['wat'],
             ['analyze','--pcap',root/'samples/demo.pcap','--duration','1'],
             ['capture','--interface','lo','--duration','nan'],['capture','--interface','lo','--duration','0'],
             ['analyze','--pcap',root/'samples/demo.pcap','--count','1x'],
             ['analyze','--pcap',root/'samples/demo.pcap','--ids','--no-ids'],
             ['analyze','--pcap',root/'samples/demo.pcap','--ids','--ids'],
             ['analyze','--pcap',root/'samples/demo.pcap','--report','pdf'],
             ['analyze','--pcap',root/'samples/demo.pcap','--output','foo'],
             ['interfaces','--count','1']]:
    run(args,2)

with tempfile.TemporaryDirectory(prefix='packetforge-tests-') as temp:
    temp = Path(temp)
    expected = json.loads((root/'samples/expected.json').read_text())
    for name, case in expected.items():
        prefix = temp / name
        result = run(['analyze','--pcap',root/'samples'/name,'--rules',root/'config/rules.json','--report','all','--output',prefix])
        report = json.loads(Path(str(prefix)+'.json').read_text())
        assert report['statistics']['packets'] == case['packets'], name
        assert sorted(a['rule_id'] for a in report['alerts']) == sorted(case['alerts']), (name,report['alerts'])
        assert report['metadata']['ids_enabled'] is True
        assert report['statistics']['total_ids_alerts'] == len(case['alerts'])
        for alert in report['alerts']:
            assert alert['observed_count'] >= alert['threshold']
            for key in ['alert_id','rule_id','title','timestamp','severity','source','destination',
                        'detection_window_seconds','observed_count','threshold','evidence','confidence',
                        'limitations','recommendation','mitre_technique']:
                assert key in alert, (name,key)
        with Path(str(prefix)+'-alerts.csv').open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        assert len(rows) == len(report['alerts'])
        if rows: assert json.loads(rows[0]['evidence']) == report['alerts'][0]['evidence']
        with Path(str(prefix)+'-flows.csv').open(newline='') as stream:
            assert len(list(csv.DictReader(stream))) == len(report['flows'])
        html = Path(str(prefix)+'.html').read_text()
        assert '<h1>PacketForge</h1>' in html and 'Investigation limitations' in html
        assert '<script' not in html and 'http-equiv="Content-Security-Policy"' in html
        if name == 'malformed.pcap':
            assert report['statistics']['truncated']==1 and report['statistics']['malformed']==1
        if name == 'normal_tcp.pcap':
            assert report['statistics']['unique_flows']==2 and report['flows'][0]['packets']==3
        if name == 'synrate.pcap':
            assert report['alerts'][0]['observed_count']==100
        # Overwriting a previous report is a clear error.
        run(['analyze','--pcap',root/'samples'/name,'--report','json','--output',prefix],2)

    for name in ['big_endian.pcap','nanosecond.pcap','empty.pcap']:
        prefix=temp/name
        run(['analyze','--pcap',root/'samples'/name,'--report','json','--output',prefix])
        report=json.loads(Path(str(prefix)+'.json').read_text())
        if name=='nanosecond.pcap': assert report['metadata']['first_packet'].endswith('.123456789Z')
        if name=='empty.pcap': assert report['statistics']['packets_per_second'] is None
    for name in ['out_of_order.pcap','unsupported_link.pcap']:
        run(['analyze','--pcap',root/'samples'/name],2)
    (temp/'bad.pcap').write_bytes(bytes.fromhex('0a0d0d0a')+bytes(24))
    assert 'PCAPNG' in run(['analyze','--pcap',temp/'bad.pcap'],2).stderr
    (temp/'short.pcap').write_bytes((root/'samples/demo.pcap').read_bytes()[:-1])
    run(['analyze','--pcap',temp/'short.pcap'],2)
    policy=run(['analyze','--pcap',root/'samples/sensitive.pcap','--policy','--no-ids'])
    assert 'WOULD_BLOCK' in policy.stdout and 'IDS alerts: 0' in policy.stdout
    assert 'Packets: 1' in run(['analyze','--pcap',root/'samples/demo.pcap','--count','1']).stdout
    assert 'POSSIBLE_TCP_PORT_SCAN' not in run(['analyze','--pcap',root/'samples/portscan.pcap','--no-ids']).stdout
    config=temp/'rules.json'
    bad_configs=['{', '{"unknown":1}', '{"rules":{"TYPO":{}}}',
        '{"rules":{"POSSIBLE_TCP_PORT_SCAN":{"threshold":1}}}',
        '{"rules":{"HIGH_TCP_SYN_RATE":{"enabled":"false"}}}',
        '{"rules":{"HIGH_TCP_SYN_RATE":{"threshold":1.5}}}',
        '{"rules":{"HIGH_TCP_SYN_RATE":{"threshold":18446744073709551615}}}',
        '{"rules":{"HIGH_TCP_SYN_RATE":{"severity":"CRITICAL"}}}',
        '{"rules":{"HIGH_TCP_SYN_RATE":{"window_seconds":0}}}',
        '{"rules":{"HIGH_TCP_SYN_RATE":{"exclude_sources":["192.0.2.0/24"]}}}',
        '{"rules":{"SENSITIVE_SERVICE_TRAFFIC":{"ports":[]}}}',
        '{"rules":{},"rules":{}}', '{"limits":{"max_flows":0}}',
        '{"policy":[{"action":"DROP"}]}', '['*40+'0'+']'*40]
    for bad in bad_configs:
        config.write_text(bad)
        run(['analyze','--pcap',root/'samples/demo.pcap','--rules',config],2)
    config.write_text(json.dumps({'rules':{'POSSIBLE_TCP_PORT_SCAN':{'exclude_sources':['192.0.2.10']}}}))
    assert 'IDS alerts: 0' in run(['analyze','--pcap',root/'samples/portscan.pcap','--rules',config]).stdout
    config.write_text(json.dumps({'rules':{'POSSIBLE_TCP_PORT_SCAN':{'enabled':False}}}))
    assert 'IDS alerts: 0' in run(['analyze','--pcap',root/'samples/portscan.pcap','--rules',config]).stdout
    # Malicious filename is metadata, escaped into standalone HTML.
    evil=temp/'<img src=x onerror=alert(1)>.pcap'
    evil.write_bytes((root/'samples/demo.pcap').read_bytes())
    run(['analyze','--pcap',evil,'--report','html','--output',temp/'escaped'])
    html=(temp/'escaped.html').read_text()
    assert '<img src=x' not in html and '&lt;img src=x' in html

print(f'{checks} CLI/fixture subprocess checks passed; JSON, CSV, HTML and config assertions passed')
