#!/usr/bin/env python
from __future__ import print_function, division, absolute_import
import argparse
import subprocess
import netifaces
import time
import signal
import sys
import tempfile

from katsdptelstate.endpoint import endpoint_list_parser


def interface_address(iface):
    return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('endpoints', type=endpoint_list_parser(7148), help='Multicast groups',
                        metavar='ADDR+N:PORT')
    parser.add_argument('output', type=str, help='Output file')
    parser.add_argument('--interface', type=str, default='p5p1',
                        help='Network interfaces')
    parser.add_argument('--tmpdir', type=str, default='/mnt/ramdisk0',
                        help='Temporary directory (should be a ramdisk, or use --direct-io)')
    parser.add_argument('--direct-io', action='store_true',
                        help='Use Direct I/O for packet capture')
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
        mcdump_args = [
            'hwloc-bind', 'os={}'.format(args.interface), '--',
            'mcdump', '-i', interface_address(args.interface),
            '--collect-cpu', str(cores[0]),
            '--network-cpu', str(cores[1]),
            '--disk-cpu', str(cores[2]),
            pcap_file.name]
        mcdump_args += [str(endpoint) for endpoint in args.endpoints]
        if args.direct_io:
            mcdump_args.append('--direct-io')
        mcdump = subprocess.Popen(mcdump_args)
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
