#!/usr/bin/env python
from __future__ import print_function, division, absolute_import
import argparse
import socket
import subprocess
import netifaces
import struct
import time
import signal
import sys
import tempfile
import contextlib

def option_pair(base_type):
    def fn(value):
        parts = value.split(',', 1)
        if len(parts) == 1:
            out = base_type(parts[0])
            return out, out
        else:
            out0 = base_type(parts[0])
            out1 = base_type(parts[1])
            return out0, out1
    return fn


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('address', type=option_pair(str), help='Multicast groups')
    parser.add_argument('output', type=str, help='Output file')
    parser.add_argument('--port', type=option_pair(int), default='7148', help='UDP ports')
    parser.add_argument('--interface', type=option_pair(str), default='p5p1,p4p1', help='Network interfaces')
    parser.add_argument('--tmpdir', type=option_pair(str), default='/mnt/ramdisk0,/mnt/ramdisk1', help='Temporary directories (should be ramdisks)')
    parser.add_argument('-s', '--seconds', type=float, default=5, help='Length of capture')
    parser.add_argument('--heaps', type=int, help='Maximum number of heaps to convert')
    parser.add_argument('--non-icd', action='store_true', help='Assume digitiser is not ICD compliant')
    return parser.parse_args()


def subscribe(sock, address, interface):
    if_address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    if_address_raw = socket.inet_aton(if_address)
    address_raw = socket.inet_aton(address)
    mreq = struct.pack('4s4s', address_raw, if_address_raw)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


def main():
    args = parse_args()
    pcap_file = []
    for i in range(2):
        pcap_file.append(tempfile.NamedTemporaryFile(suffix='.pcap', dir=args.tmpdir[i]))
    # Socket for multicast subscriptions
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with contextlib.closing(sock), pcap_file[0], pcap_file[1]:
        for i in range(2):
            subscribe(sock, args.address[i], args.interface[i])
        # Capture data
        tcpdump = []
        for i in range(2):
            tcpdump.append(subprocess.Popen(
                ['hwloc-bind', 'os={}'.format(args.interface[i]), '--',
                 'tcpdump', '-i', args.interface[i], '-n', '-p', '-q', '-s', '8192', '-B', '4096',
                 'ip proto \\udp and dst port {} and dst host {}'.format(args.port[i], args.address[i]),
                 '-w', pcap_file[i].name
                ]))
        time.sleep(args.seconds)
        for i in range(2):
            tcpdump[i].send_signal(signal.SIGINT)
        for i in range(2):
            ret = tcpdump[i].wait()
            if ret != 0:
                print('tcpdump returned exit code {}'.format(ret), file=sys.stderr)
                return 1

        decode_cmd = ['digitiser_decode']
        if args.non_icd:
            decode_cmd.append('--non-icd')
        if args.heaps is not None:
            decode_cmd.extend(['--heaps', str(args.heaps)])
        decode_cmd.extend([pcap_file[0].name, pcap_file[1].name, args.output])
        return subprocess.call(decode_cmd)


if __name__ == '__main__':
    sys.exit(main())
