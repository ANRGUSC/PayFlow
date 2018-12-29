
# PayFlow
PayFlow provides QoS (Quality of Service) in the form of bandwidth reservations to hosts in an OpenFlow-based software-defined network in return for micropayments. It uses the POX controller and OpenVSwitch for switches. 

## Protocol
See document folder for the paper describing PayFlow


## Dependencies
 1. Mininet (2.2.2 confirmed working) 
 2. OpenVSwitch (2.9.0 confirmed working)
 
## Directory Structure
/pox/ext

	Directory containing controller code
/dynamicp

	- client.py
	Client code for making QoS requests
	- queue_setup.py
	Script that sets up the static queues on each interface
	- mininet_setup_dynamicp.py 
	Script that sets up Mininet network, iperf servers and queues. Not required.


## How to Run
First, setup the controller using:

	sudo python pox/pox.py price_dynamic_payments openflow.discovery host_tracker

Then instantiate the Mininet network:

	sudo mn --controller remote,ip=127.0.0.1 --custom topo.py --topo mytopo

Setup queues using:

	sudo python dynamicp/queue_setup.py

Cleanup using:

	sudo fuser -k 6653/tcp #openflow
	sudo fuser -k 6633/tcp #openflow
	sudo fuser -k 7790/tcp #messenger
	sudo fuser -k 6113/tcp #broker