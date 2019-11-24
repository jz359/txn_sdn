#!/usr/bin/env python2
import argparse
import grpc
import json
import os
import Queue
import socket
import sys
import threading
from time import sleep
from scapy.all import sniff, sendp, send, get_if_list, get_if_hwaddr, srp1, sr1, bind_layers
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


def vote_pkt(txn_id, txn_mgr, iface):
    bind_layers(Ether, Vote, type=0x9999)
    bind_layers(TwoPCPhase, Vote, phase=0)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x9999)
    pkt = pkt / TwoPCPhase(phase=0) / Vote(txn_mgr=txn_mgr, txn_id=txn_id)
    return pkt

def release_pkt(txn_id, txn_mgr, iface):
    bind_layers(Ether, Release, type=0x9999)
    bind_layers(TwoPCPhase, Release, phase=2)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /TwoPCPhase(phase=2) / Release(txn_mgr=txn_mgr, txn_id=txn_id)
    return pkt

def commit_pkt(txn_id, txn_mgr, iface):
    bind_layers(Ether, Commit, type=0x9999)
    bind_layers(TwoPCPhase, Commit, phase=3)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /TwoPCPhase(phase=3) / Commit(txn_mgr=txn_mgr, txn_id=txn_id)
    return pkt


def get_if(sw):
    ifs=get_if_list()
    target = 'ctlr-' + sw
    iface=None
    for i in get_if_list():
        if target in i:
            iface=i
            break;
    if not iface:
        print "Cannot find target interface " + target
        exit(1)
    return iface


def print_pkt(pkt):
    pkt.show2()
    sys.stdout.flush()


class Sniffer(threading.Thread):
    def __init__(self, iface, queue):
        super(Sniffer, self).__init__()
        self.iface = iface
        self.queue = queue


    def run(self):
        sniff(iface = self.iface, # "ctlr-s1"
           filter='ether proto 0x9999 and ether src ff:ff:ff:ff:ff:ff', 
          prn = lambda x: self.add_pkt(x))


    def add_pkt(self, pkt):
    	if (pkt.src == 'ff:ff:ff:ff:ff:ff'):
    		self.queue.put(pkt)
    		sys.exit(0)

class Runner(threading.Thread):
    def __init__(self, txn_mgr, txn_id, phase, sw):
        super(Runner, self).__init__()
        self.txn_mgr = txn_mgr
        self.txn_id = txn_id
        self.phase = phase
        self.sw = sw
        self.queue = Queue.Queue()
        self.sniffer = Sniffer(iface="ctlr-"+self.sw, queue=self.queue)
        self.sniffer.start()


    def run_vote(self):
        iface = get_if(self.sw)
        pkt = vote_pkt(self.txn_id, self.txn_mgr, iface)
        print('running vote')
        sendp(pkt, iface=iface, verbose=False)
        resp_pkt = self.queue.get()
        print_pkt(resp_pkt)
        # TODO parse for response and return
        return 0 # success


    def run_release(self):
        iface = get_if(self.sw)
        pkt = release_pkt(self.txn_id, self.txn_mgr, iface)
        print('running release')
        sendp(pkt, iface=iface, verbose=False)
        resp_pkt = self.queue.get()
        print_pkt(resp_pkt)
        # TODO parse for response and return
        return 0 # success


    def run_commit(self):
        iface = get_if(self.sw)
        pkt = commit_pkt(self.txn_id, self.txn_mgr, iface)
        print('running commit')
        sendp(pkt, iface=iface, verbose=False)
        resp_pkt = self.queue.get()
        print_pkt(resp_pkt)
        # TODO parse for response and return
        return 0 # success


    def run(self):
        global response_list, got_all_responses, access_lock, PARTICIPANTS
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

        # done running a phase
        print("runner for " + self.sw + " done running phase: " + self.phase)
        sys.exit(0)


class TransactionManager(object):
    def __init__(self, txn_mgr):
        self.txn_mgr = txn_mgr
        # map of txn_id to JSON of updates to apply once every lock is held
        # see api.json
        self.updates = {}


    def run_txn(self, txn_id, updates):
        global response_list, got_all_responses, access_lock, PARTICIPANTS
        self.updates[txn_id] = updates
        # TODO create and spawn Runner threads for each switch in [updates]
        # set PARTICIPANTS, start the threads, and wait on the cv
        # gather responses, delete threads, and repeat for each phase 
        r = Runner(100,200,"vote", "s1")
        r.start()
        with access_lock:
            while (len(response_list.keys()) < PARTICIPANTS):
                got_all_responses.wait()

        num_nacks = 0
        ack_switches = set()
        for sw, response in response_list.items():
            if response:
                num_nacks += 1
            else:
                ack_switches.add(sw)

        if num_nacks > 0:
            print('cannot acquire all locks; proceeding to release phase')
            # TODO release phase and exit
            sys.exit(1)

        # else, got all acks so proceed to commit phase

        # TODO apply_txn here

        r = Runner(100,200,'commit', 's1')
        r.start()
        with access_lock:
            while (len(response_list.keys()) < PARTICIPANTS):
                got_all_responses.wait()

        num_nacks = 0
        ack_switches = set()
        for sw, response in response_list.items():
            if response:
                num_nacks += 1
            else:
                ack_switches.add(sw)

        print('commit phase done and all locks were released!')


    def apply_txn(self, txn_id):
        updates = self.updates[txn_id]
        for update_name, update in updates.items():
            sw = str(update["SWITCH"])
            match_field_tuples = {str(k):(str(v[0]), v[1]) for k,v in update["MATCH_FIELDS"].items()}
            action_params = {str(k):v for k,v in update['ACTION_PARAMS'].items()}
            addForwardingRule(sw, str(update["TABLE_NAME"]), match_field_tuples, str(update["ACTION"]), action_params)


def addForwardingRule(switch, table_name, match_fields, action_name, action_params):
    # Helper function to install forwarding rules
    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        action_name=action_name,
        action_params=action_params)
    bmv2_switch = switches[switch]
    bmv2_switch.WriteTableEntry(table_entry)
    print "Installed rule on %s" % (switch)

def main(p4info_file_path, bmv2_file_path, topo_file_path, sw_config_file_path, controller_id):
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
        # addForwardingRule("s1", "10.0.1.11", 1)
        # addForwardingRule("s1", "10.0.2.22", 2)
        # addForwardingRule("s1", "10.0.3.33", 3)

        # addForwardingRule("s2", "10.0.1.11", 2)
        # addForwardingRule("s2", "10.0.2.22", 1)
        # addForwardingRule("s2", "10.0.3.33", 3)

        # addForwardingRule("s3", "10.0.1.11", 2)
        # addForwardingRule("s3", "10.0.2.22", 3)
        # addForwardingRule("s3", "10.0.3.33", 1)

        # TODO enter loop and prompt user input for JSON file of txn
        # txn_mgr = TransactionManager(1)
        # txn_mgr.run_txn(9,None)
        with open(sw_config_file_path) as f:
            sw_config_json = json.load(f)
            txn_mgr = TransactionManager(controller_id)
            txn_mgr.run_txn(controller_id, sw_config_json)
            # txn_mgr.apply_txn(controller_id)
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
    parser.add_argument('--sw_config', help='New configuration for switches', type=str, action="store", required=False, default='sw.config')
    parser.add_argument('--id', help='Controller id', type=int, action="store", required=False, default=0)
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
    if not os.path.exists(args.sw_config):
        parser.print_help()
        print "\nSwitch config file not found: %s" % args.sw_config
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.topo, args.sw_config, args.id)

    
