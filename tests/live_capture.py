#!/usr/bin/env python3
"""Opt-in AF_PACKET checks. Run only in an isolated network namespace (see TESTING.md)."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

binary=Path(sys.argv[1]).resolve()
assert os.environ.get('PACKETFORGE_ISOLATED_TEST')=='1', 'Run in the documented isolated network namespace'
subprocess.run(['ip','link','set','lo','up'],check=True)
result=subprocess.run([str(binary),'interfaces'],capture_output=True,text=True,check=True)
assert 'lo' in result.stdout
with tempfile.TemporaryDirectory(prefix='packetforge-live-') as directory:
    prefix=Path(directory)/'count'
    command=[str(binary),'capture','--interface','lo','--count','4','--duration','5','--no-ids','--report','json','--output',str(prefix)]
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
        receiver.bind(('127.0.0.1',0))
        time.sleep(0.3)
        for _ in range(6):
            sender.sendto(b'PacketForge loopback self-test',receiver.getsockname())
            time.sleep(0.02)
    stdout,stderr=process.communicate(timeout=7)
    assert process.returncode==0,(stdout,stderr)
    report=json.loads(prefix.with_suffix('.json').read_text())
    assert report['statistics']['packets']==4,report['statistics']
    assert report['statistics']['protocols']['UDP']==4,report['statistics']
    assert report['statistics']['malformed']==0 and report['statistics']['truncated']==0
    assert report['flows'] and report['metadata']['source']=='lo'
    print(stdout)
    start=time.monotonic()
    result=subprocess.run([str(binary),'capture','--interface','lo','--duration','0.3','--quiet'],capture_output=True,text=True,timeout=3)
    elapsed=time.monotonic()-start
    assert result.returncode==0 and 0.25<=elapsed<2,(elapsed,result.stderr)
    prefix=Path(directory)/'signal'
    process=subprocess.Popen([str(binary),'capture','--interface','lo','--duration','10','--report','json','--output',str(prefix)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    time.sleep(0.3)
    process.send_signal(signal.SIGINT)
    stdout,stderr=process.communicate(timeout=3)
    assert process.returncode==0,(stdout,stderr)
    assert json.loads(prefix.with_suffix('.json').read_text())['metadata']['interrupted'] is True
    # Binding to a real Ethernet device is also exercised without external connectivity.
    subprocess.run(['ip','link','add','pf-test0','type','veth','peer','name','pf-test1'],check=True)
    subprocess.run(['ip','link','set','pf-test0','up'],check=True)
    result=subprocess.run([str(binary),'capture','--interface','pf-test0','--duration','0.2','--promiscuous'],capture_output=True,text=True,timeout=3)
    assert result.returncode==0,result.stderr
    assert 'promiscuous' in result.stdout
print('Live capture verified: real UDP frames, count limit, idle duration, Ctrl+C, Ethernet binding and explicit promiscuous membership')
