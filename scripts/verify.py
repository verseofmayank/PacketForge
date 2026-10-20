#!/usr/bin/env python3
"""Reproducible clean build and offline validation; preserves real command output."""
import argparse
from pathlib import Path
import subprocess
import sys

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--build-dir',default='build-verify')
parser.add_argument('--sanitize',action='store_true')
args=parser.parse_args()
build=Path(args.build_dir).resolve()
logs=root/'docs/evidence'
logs.mkdir(exist_ok=True)
name='sanitizers' if args.sanitize else 'build-and-tests'
commands=[['cmake','-S',str(root),'-B',str(build),'-DCMAKE_BUILD_TYPE='+('Debug' if args.sanitize else 'Release'),
           '-DPACKETFORGE_SANITIZERS='+('ON' if args.sanitize else 'OFF')],
          ['cmake','--build',str(build),'--clean-first','-j','2'],
          ['ctest','--test-dir',str(build),'-LE','host','--output-on-failure'],
          [str(build/'packetforge_tests')],
          [sys.executable,str(root/'tests/integration.py'),str(build/'packetforge'),str(root)]]
with (logs/(name+'.txt')).open('w') as log:
    for command in commands:
        line='$ '+' '.join(command)+'\n'
        print(line,end='',flush=True);log.write(line);log.flush()
        process=subprocess.Popen(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        for line in process.stdout:
            print(line,end='',flush=True);log.write(line)
        status=process.wait()
        if status:
            log.write(f'Command failed with exit code {status}\n')
            raise SystemExit(status)
print(f'Verification log: {logs/(name+".txt")}')
