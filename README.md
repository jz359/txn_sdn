# txn_sdn
supporting transactional semantics for network updates in SDNs


## References
Paxos made Switch-y:
NetPaxos: https://github.com/open-nfpsw/NetPaxos/blob/master/src/acceptor.p4

## TODOs
- assigning txn ids, txn mgr
- send: how to send from controller to switch 
	- def pkt structure [https://scapy.readthedocs.io/en/latest/build_dissect.html]
	- send [https://thepacketgeek.com/scapy-p-06-sending-and-receiving-with-scapy/]
- receive
    - how can controller listen to pkts directed to it from p4 [see scapy - use sr function + callbacks]
    - processing packets [helper functions - see scapy]
- listen to sdn app

## Timeline
- on oct 25: write skeleton code for TM (python) and RM (P4) 
- on nov 1: have 2PC working btwn controller (TM) and switch(es) (RMs)
- on nov 8: have 2PC completely done; start on SS2PL
- on nov 15: finish testing
- on nov 25: simple demos for atomic/transactional semantics 





