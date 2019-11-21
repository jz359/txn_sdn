#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "enp0s3" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find enp0s3 interface"
        exit(1)
    return iface

def main():
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str('10.0.1.11'))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(src='10.0.2.15',dst='10.0.1.11')
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
