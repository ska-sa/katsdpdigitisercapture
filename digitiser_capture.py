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
    parser.add_argument('--interface', type=option_pair(str), default='p5p1,p4p1',
                        help='Network interfaces')
    parser.add_argument('--tmpdir', type=option_pair(str), default='/mnt/ramdisk0,/mnt/ramdisk1',
                        help='Temporary directories (should be ramdisks)')
    parser.add_argument('-s', '--seconds', type=float, default=5, help='Length of capture')
    parser.add_argument('--heaps', type=int, help='Maximum number of heaps to convert')
    parser.add_argument('--keep', action='store_true', help='Do not delete the pcap files')
    parser.add_argument('--non-icd', action='store_true',
                        help='Assume digitiser is not ICD compliant')
    return parser.parse_args()


def main():
    args = parse_args()
    pcap_file = []
    for i in range(2):
        pcap_file.append(tempfile.NamedTemporaryFile(
            suffix='.pcap', dir=args.tmpdir[i], delete=not args.keep))
    with pcap_file[0], pcap_file[1]:
        # Capture data
        mcdump = []
        for i in range(2):
            # Determine which cores are local to the NIC
            cores = subprocess.check_output(
                ['hwloc-calc', '--intersect', 'pu', '--physical',
                 'os={}'.format(args.interface[i])])
            cores = [int(x) for x in cores.decode('ascii').split(',')]
            # Allocate cores in a way that spreads load even if the NICs
            # are on the same CPU socket
            if i == 1:
                cores.reverse()
            while len(cores) < 3:
                cores += cores
            mcdump.append(subprocess.Popen(
                ['hwloc-bind', 'os={}'.format(args.interface[i]), '--',
                 'mcdump', '-i', interface_address(args.interface[i]),
                 '--collect-cpu', str(cores[0]),
                 '--network-cpu', str(cores[1]),
                 '--disk-cpu', str(cores[2]),
                 pcap_file[i].name, '{}:{}'.format(args.address[i], args.port[i])]))
        time.sleep(args.seconds)
        for i in range(2):
            mcdump[i].send_signal(signal.SIGINT)
        for i in range(2):
            ret = mcdump[i].wait()
            if ret != 0:
                print('mcdump returned exit code {}'.format(ret), file=sys.stderr)
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
