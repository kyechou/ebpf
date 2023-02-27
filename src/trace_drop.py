#!/usr/bin/env python

from bcc import BPF
from bcc.utils import printb
import ctypes as ct

# https://github.com/nhorman/dropwatch/blob/master/src/lookup.c

IFNAMSIZ = 16
ETH_ALEN = 6


class DropData(ct.Structure):
    _fields_ = [
        # L1, auxiliary
        ('ifindex', ct.c_int),
        ('ingress_ifindex', ct.c_int),
        ('location', ct.c_char_p),
        ('tstamp', ct.c_uint64),
        ('reason', ct.c_int),
        # L2
        ('eth_dst_addr', ct.c_char * ETH_ALEN),
        ('eth_src_addr', ct.c_char * ETH_ALEN),
        ('eth_proto', ct.c_uint16),
        # L3
        ('tot_len', ct.c_uint16),
        ('ip_proto', ct.c_uint8),
        ('saddr', ct.c_uint32),
        ('daddr', ct.c_uint32),
        # L4
    ]


def print_pkt_drop(ctx, data, size):
    event = ct.cast(data, ct.POINTER(DropData)).contents
    print('[' + str(event.tstamp / 1e9) + ']', event.ifindex,
          event.ingress_ifindex, 'ip_src:', event.saddr, 'ip_dst:', event.daddr,
          'proto:', event.ip_proto)


def main():
    b = BPF(src_file='network.c', cflags=['-fcf-protection'])

    b["pkt_drops"].open_ring_buffer(print_pkt_drop)
    print('Ready')

    while 1:
        try:
            b.ring_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == '__main__':
    main()
