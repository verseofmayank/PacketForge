#!/usr/bin/env python3
"""Deterministic, synthetic classic PCAPs. Python standard library only; no traffic sent."""
import ipaddress
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BASE = 1700000000

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def ethernet(payload, kind=0x0800, vlan=None):
    macs = bytes.fromhex('020000000002020000000001')
    if vlan is not None:
        return macs + struct.pack('!HHH', 0x8100, vlan, kind) + payload
    return macs + struct.pack('!H', kind) + payload

def ipv4(payload, proto=6, src='192.0.2.10', dst='198.51.100.20', flags=0, options=b''):
    source, destination = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    header = struct.pack('!BBHHHBBH4s4s', 0x45 + len(options)//4, 0, 20+len(options)+len(payload), 1, flags, 64, proto, 0, source, destination) + options
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + payload

def tcp(port=443, sport=40000, flags=2, seq=1, src='192.0.2.10', dst='198.51.100.20'):
    segment = struct.pack('!HHIIBBHHH', sport, port, seq, 0, 0x50, flags, 65535, 0, 0)
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + struct.pack('!BBH',0,6,len(segment))
    segment = segment[:16] + struct.pack('!H',checksum(pseudo+segment)) + segment[18:]
    return ethernet(ipv4(segment,src=src,dst=dst))

def udp(payload=b'hello', port=5353):
    # A zero UDP checksum is legal for IPv4.
    segment=struct.pack('!HHHH',42000,port,len(payload)+8,0)+payload
    return ethernet(ipv4(segment,17))

def icmp(reply=False):
    body=struct.pack('!BBHHH',0 if reply else 8,0,0,1,1)+b'PacketForge'
    body=body[:2]+struct.pack('!H',checksum(body))+body[4:]
    return ethernet(ipv4(body,1))

def arp():
    body=struct.pack('!HHBBH',1,0x0800,6,4,1)+bytes.fromhex('020000000001')+ipaddress.ip_address('192.0.2.10').packed
    body+=bytes(6)+ipaddress.ip_address('192.0.2.20').packed
    return ethernet(body,0x0806)

def ipv6():
    src=ipaddress.ip_address('2001:db8::1').packed; dst=ipaddress.ip_address('2001:db8::2').packed
    body=struct.pack('!BBHHH',128,0,0,1,1)
    pseudo=src+dst+struct.pack('!I3xB',len(body),58)
    body=body[:2]+struct.pack('!H',checksum(pseudo+body))+body[4:]
    return ethernet(struct.pack('!IHBB',6<<28,len(body),58,64)+src+dst+body,0x86dd)

def write(name, packets, endian='<', nano=False, linktype=1):
    path=ROOT/'samples'/name
    with path.open('wb') as output:
        output.write(struct.pack(endian+'IHHIIII',0xa1b23c4d if nano else 0xa1b2c3d4,2,4,0,0,262144,linktype))
        for i,entry in enumerate(packets):
            packet, wire, offset = entry if isinstance(entry,tuple) else (entry,len(entry),i*100_000_000)
            seconds, nanos=divmod(offset,1_000_000_000)
            output.write(struct.pack(endian+'IIII',BASE+seconds,nanos if nano else nanos//1000,len(packet),wire))
            output.write(packet)

def generate():
    (ROOT/'samples').mkdir(exist_ok=True)
    normal=[tcp(),tcp(40000,443,0x12,src='198.51.100.20',dst='192.0.2.10'),tcp(flags=0x10),tcp(flags=0x11)]
    dns=struct.pack('!HHHHHH',1,0x0100,1,0,0,0)+b'\x07example\x04test\0'+struct.pack('!HH',1,1)
    cases={'normal_tcp.pcap':normal,'normal_udp_dns.pcap':[udp(),udp(dns,53)],'arp.pcap':[arp()],
           'icmp.pcap':[icmp(),icmp(True)],'portscan.pcap':[tcp(port=1000+i) for i in range(13)],
           'synrate.pcap':[tcp(seq=i) for i in range(101)],'icmp_rate.pcap':[icmp() for _ in range(51)],
           'concentration.pcap':[tcp(sport=40000+i) for i in range(41)],'sensitive.pcap':[tcp(port=22)],
           'ipv6.pcap':[ipv6()], 'demo.pcap':normal+[udp(dns,53),arp(),icmp(),icmp(True),ipv6()]}
    # Keep all rate scenarios inside the 10-second demonstration window.
    for name,packets in cases.items():
        write(name,[(p,len(p),i*50_000_000) for i,p in enumerate(packets)])
    bad=bytearray(tcp());bad[14]=0x44
    cases['malformed.pcap']=[(tcp()[:25],54,0),(bytes(bad),54,100_000_000)]
    write('malformed.pcap',cases['malformed.pcap'])
    write('mixed.pcap',normal+[arp(),udp(dns,53),icmp(),ipv6()]+[tcp(port=1000+i) for i in range(13)])
    write('nanosecond.pcap',[(tcp(),54,123456789)],nano=True)
    write('big_endian.pcap',[tcp()],endian='>')
    write('out_of_order.pcap',[(tcp(),54,1_000_000_000),(tcp(),54,0)])
    write('unsupported_link.pcap',[tcp()],linktype=101)
    write('empty.pcap',[])
    expected={name:{'packets':len(packets),'alerts':[]} for name,packets in cases.items()}
    expected['portscan.pcap']['alerts']=['POSSIBLE_TCP_PORT_SCAN']
    expected['synrate.pcap']['alerts']=['HIGH_TCP_SYN_RATE']
    expected['icmp_rate.pcap']['alerts']=['HIGH_ICMP_ECHO_RATE']
    expected['concentration.pcap']['alerts']=['CONNECTION_CONCENTRATION']
    expected['sensitive.pcap']['alerts']=['SENSITIVE_SERVICE_TRAFFIC']
    expected['mixed.pcap']={'packets':21,'alerts':['POSSIBLE_TCP_PORT_SCAN']}
    (ROOT/'samples'/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
    print(f'Generated synthetic PCAPs in {ROOT / "samples"}')

if __name__=='__main__':
    generate()
