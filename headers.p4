/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  switch_port_t;

#define MAX_CHANGES 10
const bit<16> 		 TYPE_IPV4 = 0x800;
const switch_port_t  CONTROLLER_PORT = 255;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

@controller_header("packet_in")
header packet_in_header_t {
	switch_port_t ingress_port;
	bit<7>        padding;
}

@controller_header("packet_out")
header packet_out_header_t {
	switch_port_t egress_port;
	bit<7>        padding;
}

/* BEGIN TXN_SDN HEADERS */

/* mgr --> switch */

/* vote request from txn mgr */
header vote_t {
    bit<8>    txn_mgr;
    bit<8>    txn_id;
}

/* vote reply to txn mgr */
header confirm_t {
    bit<8>    txn_mgr;
    bit<8>    txn_id;
    bit<1>    status;
}

/* txn mgr telling us to release the lock if we hold it for them */
header release_t {
	bit<8>    txn_mgr;
    bit<8>    txn_id;
}

/* commit reply from txn mgr: basically telling us to release the lock but only on successful txn */
header commit_t {
    bit<8>    txn_mgr;
    bit<8>    txn_id;
}

/* commit ack to txn mgr */
header finished_t {
    bit<8>    txn_mgr;
    bit<8>    txn_id;
}

header 2pc_phase_t {
    bit<3>  phase;
}
header_union 2pc_t {
	vote_t          vote;
    commit_t        commit;
    confirm_t       confirm;
    release_t       release;
    finished_t      finished;
}
