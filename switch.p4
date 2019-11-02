/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

const bit<8> TYPE_2PC_PHASE = 0xFD;
const bit<3> TYPE_VOTE = 0;
const bit<3> TYPE_CONFIRM = 1;
const bit<3> TYPE_RELEASE = 2;
const bit<3> TYPE_COMMIT = 3;
const bit<3> TYPE_FINISHED = 4;

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    2pc_phase_t			2pc_phase;
    2pc_t               2pc;
    packet_in_header_t  packet_in;
    packet_out_header_t packet_out;
}

register lock_txn_mgr {
    width: 8;
    instance_count: 1;
}

register lock_txn_id {
    width: 8;
    instance_count: 1;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
        	TYPE_2PC_PHASE: parse_2pc_phase;
        	default: accept;
        }
    }

    state parse_2pc_phase {
    	packet.extract(hdr.2pc_phase);
    	transition select(hdr.2pc_phase.phase) {
    		TYPE_VOTE: parse_2pc_vote;
    		TYPE_CONFIRM: parse_2pc_confirm;
    		TYPE_RELEASE: parse_2pc_release;
    		TYPE_COMMIT: parse_2pc_commit;
    		TYPE_FINISHED: parse_2pc_finished;
    		default: accept;
    	}
    }

    state parse_2pc_vote {
    	packet.extract(hdr.2pc.vote);
    	transition accept;
    }
    state parse_2pc_confirm {
    	packet.extract(hdr.2pc.confirm);
    	transition accept;
    }
    state parse_2pc_release {
    	packet.extract(hdr.2pc.release);
    	transition accept;
    }
    state parse_2pc_commit {
    	packet.extract(hdr.2pc.commit);
    	transition accept;
    }
    state parse_2pc_finished {
    	packet.extract(hdr.2pc.finished);
    	transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action send_to_controller() {
        standard_metadata.egress_spec = CONTROLLER_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action construct_confirm() {
        if (lock_txn_id == hdr.2pc.vote.txn_id && lock_txn_mgr == hdr.2pc.vote.txn_mgr) {
            // TODO populate the confirm header and send to cntrlr
        } else {
            // same thing except set confirm.status = 0 and send to cntrlr
        }
    }
    
    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table txn {
        key = {
            hdr.2pc.vote.txn_mgr : exact;
            hdr.2pc.vote.txn_id  : exact;
        }
        actions = {
            construct_confirm;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        // Process only IPv4 packets.	
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
	        drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
