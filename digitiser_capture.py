#!/usr/bin/env python
from __future__ import print_function, division, absolute_import
import argparse
import subprocess
import netifaces
import struct
import time
import signal
import sys
import tempfile
import contextlib


def option_pair(base_type):
    def callback(value):
        parts = value.split(',', 1)
        if len(parts) == 1:
            out = base_type(parts[0])
            return out, out
        else:
            out0 = base_type(parts[0])
            out1 = base_type(parts[1])
            return out0, out1
    return callback


def interface_address(iface):
    return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('address', type=option_pair(str), help='Multicast groups')
    parser.add_argument('output', type=str, help='Output file')
    parser.add_argument('--port', type=option_pair(int), default='7148', help='UDP ports')
    parser.add_argument('--interface', type=str, default='p5p1',
                        help='Network interfaces')
    parser.add_argument('--tmpdir', type=str, default='/mnt/ramdisk0',
                        help='Temporary directories (should be ramdisks)')
    parser.add_argument('-s', '--seconds', type=float, default=5, help='Length of capture')
    parser.add_argument('--heaps', type=int, help='Maximum number of heaps to convert')
    parser.add_argument('--keep', action='store_true', help='Do not delete the pcap files')
    parser.add_argument('--non-icd', action='store_true',
                        help='Assume digitiser is not ICD compliant')
    return parser.parse_args()


def main():
    args = parse_args()
    pcap_file = tempfile.NamedTemporaryFile(
        suffix='.pcap', dir=args.tmpdir, delete=not args.keep)
    with pcap_file:
        # Determine which cores are local to the NIC
        cores = subprocess.check_output(
            ['hwloc-calc', '--intersect', 'pu', '--physical',
             'os={}'.format(args.interface)])
        cores = [int(x) for x in cores.decode('ascii').split(',')]
        while len(cores) < 3:
            cores += cores
        mcdump = subprocess.Popen(
            ['hwloc-bind', 'os={}'.format(args.interface), '--',
             'mcdump', '-i', interface_address(args.interface),
             '--collect-cpu', str(cores[0]),
             '--network-cpu', str(cores[1]),
             '--disk-cpu', str(cores[2]),
             pcap_file.name,
             '{}:{}'.format(args.address[0], args.port[0]),
             '{}:{}'.format(args.address[1], args.port[1])])
        time.sleep(args.seconds)
        mcdump.send_signal(signal.SIGINT)
        ret = mcdump.wait()
        if ret != 0:
            print('mcdump returned exit code {}'.format(ret), file=sys.stderr)
            return 1

        decode_cmd = ['digitiser_decode']
        if args.non_icd:
            decode_cmd.append('--non-icd')
        if args.heaps is not None:
            decode_cmd.extend(['--heaps', str(args.heaps)])
        decode_cmd.extend([pcap_file.name, args.output])
        return subprocess.call(decode_cmd)


if __name__ == '__main__':
    sys.exit(main())
