# txn_sdn
supporting transactional semantics for network updates in SDNs

## Approach
The writeup containing the technical approach can be found [here](https://docs.google.com/document/d/1K9XAju7q3GKRbEce-3HcnoOywvTFPqYBeW0S7S9OhiY/edit?usp=sharing)

## Running the Code
1. Run `make`. 
	* This builds the mininet topology and sets up virtual network namespaces so that the switches and the controller can communicate.
2. Run `sudo python main.py` to mimic sending updates from controller(s) to the switches. 
	* The only supported updates are insertions of new forwarding rules into switch tables.
	* Currently, `main.py` reads in desired updates from two hardcoded switch config files, and starts 1 transaction manager (representing managers on different controllers) per config file. These transaction managers begin the txn_sdn protocol concurrently. You can extend the code to support more controllers and configs by adding a transaction manager and a runner for each new config. To use your own config files, change the hardcoded switch config file names in `main.py`.
	* Write your own config file by following the format specified in `api.json`. You can view examples such as `sw.config` as well.


## Demos
* Conflicting Transactions
	* When two controllers want to run transactions with conflicting updates (i.e. involving the same switch), at least one transaction should abort and none of its rules should be applied. If the other transaction commits, it all the rules should be fully installed.
	* View demo [here](https://drive.google.com/file/d/136-fMP4Xq3R80C9C-17UgBI2nYyt74Ya/view?usp=sharing)
	* This was produced with configs in `sw.config` and `sw2.config`

* Non-Conflicting Transactions
	* When two controllers want to run transactions with non-conflicting updates, both transactions should commit. All the rules should be fully installed.
	* View demo [here](https://drive.google.com/file/d/1z9rFKjnckeOVn4U1oL9ikSD6OJ7Fxznf/view?usp=sharing)
	* This was produced with configs in `sw3.config` and `sw4.config`





