from scapy.all import sniff
import sys

def print_pkt(pkt):
    pkt.show2()
    sys.stdout.flush()


sniff(iface = "ctlr-s1",
          filter='ether proto 0x9999', 
          prn = lambda x: print_pkt(x))