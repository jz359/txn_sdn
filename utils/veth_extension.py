import argparse
import json
import subprocess



if __name__=='__main__':
	parser = argparse.ArgumentParser(description='VEth Extension')
	parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=True, default='./topology.json')
	args = parser.parse_args()

	with open(args.topo, 'r') as f:
	    topo = json.load(f)
	    switches = topo['switches'].keys()
	    
	    for sw in switches:
	    	print(sw)
	    	subprocess.call("ip link add %s-ctlr type veth peer name ctlr-%s" % (sw, sw), shell=True)
	    	subprocess.call("ip link set %s-ctlr up" % sw, shell=True)
	    	subprocess.call("ip link set ctlr-%s up" % sw, shell=True)
