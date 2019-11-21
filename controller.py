#!/usr/bin/env python2
import argparse
import grpc
import os
import socket
import sys
import threading
from time import sleep
from scapy.all import sendp, send, get_if_list, get_if_hwaddr, srp1
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, IntField, StrFixedLenField, XByteField, BitField


sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
import run_exercise
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

switches = {}
p4info_helper = None
txn_mgr = None
txn_id = 0
PARTICIPANTS = 0

response_list = {}
access_lock = threading.Lock()
got_all_responses = threading.Condition(access_lock)

class Vote(Packet):
    name = "vote"
    fields_desc = [BitField("txn_mgr", 0, 32),
                    BitField("txn_id", 0, 32)]

class Release(Packet):
    name = "release"
    fields_desc = [BitField("txn_mgr", 0, 32),
                    BitField("txn_id", 0, 32)]

class Commit(Packet):
    name = "commit"
    fields_desc = [BitField("txn_mgr", 0, 32),
                    BitField("txn_id", 0, 32)]

class TwoPCPhase(Packet):
    name = "phase"
    fields_desc = [BitField("phase", 0, 8)]

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def print_pkt(pkt):
    pkt.show2()
    sys.stdout.flush()

class Runner(threading.Thread):
    def __init__(self, txn_mgr, txn_id, phase, sw):
        super(Runner, self).__init__()
        self.txn_mgr = txn_mgr
        self.txn_id = txn_id
        self.phase = phase
        self.sw = sw

    def run_vote(self):
        iface = get_if()
        # sw_ip = socket.gethostbyname(self.sw)
        # iface = "eth0"
        pkt = vote_pkt(self.txn_id, self.txn_mgr, None, '10.0.1.11')
        pkt = srp1(pkt, iface=iface, verbose=False)
        print_pkt(pkt[0][1])
        return 0 # success

    def run_release(self):
        # TODO implement
        return 0 # success

    def run_commit(self):
        # TODO implement
        return 0 # success

    def run(self):
        global response_list, got_all_responses, access_lock
        if self.phase == "vote":
            response = self.run_vote()
        elif self.phase == "release":
            response = self.run_release()
        elif self.phase == "commit":
            response = self.run_commit()
        else:
            print("wtf")

        with access_lock:
            response_list[self.sw] = response
            if len(response_list.keys()) == PARTICIPANTS:
                got_all_responses.notifyAll()


class TransactionManager(object):
    def __init__(self, txn_mgr):
        self.txn_mgr = txn_mgr
        # map of txn_id to JSON of updates to apply once every lock is held
        # see api.json
        self.updates = {}

    def run_txn(self, txn_id, updates):
        global response_list, got_all_responses, access_lock
        self.updates[txn_id] = updates
        # TODO create and spawn Runner threads for each switch in [updates]
        # set PARTICIPANTS, start the threads, and wait on the cv
        # gather responses, delete threads, and repeat for each phase 
        r = Runner(100,200,"vote", "s1")
        r.start()


def vote_pkt(txn_id, txn_mgr, iface, ip_addr):
    pkt =  Ether(src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=ip_addr) / Vote(txn_mgr=txn_mgr, txn_id=txn_id)
    return pkt

def release_pkt(txn_id, txn_mgr, iface, ip_addr):
    pkt =  Ether(src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=ip_addr) / Release(txn_mgr=txn_mgr, txn_id=txn_id)
    return pkt

def commit_pkt(txn_id, txn_mgr, iface, ip_addr):
    pkt =  Ether(src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=ip_addr) / Commit(txn_mgr=txn_mgr, txn_id=txn_id)
    return pkt

def addForwardingRule(switch, dst_ip_addr, dst_port):
    # Helper function to install forwarding rules
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "port": dst_port,
        })
    bmv2_switch = switches[switch]
    bmv2_switch.WriteTableEntry(table_entry)
    print "Installed rule on %s to forward to %s via port %d" % (switch, dst_ip_addr, dst_port)

def main(p4info_file_path, bmv2_file_path, topo_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    global p4info_helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    

    try:
        # Establish a P4 Runtime connection to each switch
        for switch in ["s1", "s2", "s3"]:
            switch_id = int(switch[1:])
            bmv2_switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=switch,
                address="127.0.0.1:%d" % (50050 + switch_id),
                device_id=(switch_id - 1),
                proto_dump_file="logs/%s-p4runtime-requests.txt" % switch)            
            bmv2_switch.MasterArbitrationUpdate()
            print "Established as controller for %s" % bmv2_switch.name

            bmv2_switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                    bmv2_json_file_path=bmv2_file_path)
            print "Installed P4 Program using SetForwardingPipelineConfig on %s" % bmv2_switch.name
            switches[switch] = bmv2_switch
            
        # add back forwarding rules for connectivity
        addForwardingRule("s1", "10.0.1.11", 1)
        addForwardingRule("s1", "10.0.2.22", 2)
        addForwardingRule("s1", "10.0.3.33", 3)

        addForwardingRule("s2", "10.0.1.11", 2)
        addForwardingRule("s2", "10.0.2.22", 1)
        addForwardingRule("s2", "10.0.3.33", 3)

        addForwardingRule("s3", "10.0.1.11", 2)
        addForwardingRule("s3", "10.0.2.22", 3)
        addForwardingRule("s3", "10.0.3.33", 1)

        # TODO enter loop and prompt user input for JSON file of txn
        txn_mgr = TransactionManager(1)
        txn_mgr.run_txn(9,None)
    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        print "gRPC Error:", e.details(),
        status_code = e.code()
        print "(%s)" % status_code.name,
        traceback = sys.exc_info()[2]
        print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.json')
    parser.add_argument('--topo', help='Topology file',
                        type=str, action="store", required=False,
                        default='topology.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    if not os.path.exists(args.topo):
        parser.print_help()
        print "\nTopology file not found: %s" % args.topo
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.topo)

    
