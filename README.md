
# SDN Payments
SDN Payments is a forwarding system that provides QoS (Quality of Service) to hosts based on a payments system. It uses the POX controller and OpenVSwitch for switches. 

## Dependencies

 1. Mininet (2.2.2 confirmed working) 
 2. OpenVSwitch (2.9.0 confirmed working)

## Run Test
./run_network.sh [option]

Options:
	staticnr - static forwarding with no QoS requests
	staticr - static forwarding with QoS requests through TCP
	staticp - static forwarding with QoS requests through TCP. Requires payments using IOTA

### staticnr
Runs automatically. Shows bandwidth between h1 and h3 then h2 and h3.

### staticr
./run_network.sh staticr will open Mininet CLI

    
    iperf h1 h3
Tests bandwidth between h1 and h3. Should show around 200Mbit/s
Then run:

    staticr/test_client.py

Type "test" then enter. This will send a QoS request in the form of a JSON message to the controller. Communication between h1 and h3 now have level 2 (highest) priority. Now go back to Mininet console and run

    iperf h1 h3

It should shown around 500Mbit/s

### staticp
./run_network.sh staticp 

Running the above will create virtual network, create two iperf servers on host3 ports 4000 and 5000 then create queues on switch 1. Finally it will open up Mininet CLI.

Test intial configuration using: 

    iperf h1 h3

Now in a new terminal, go in sdn_payments/staticp and run 


    sudo python client.py

Follow on screen instructions and QoS should be established sucessfully.

Finally to see results, on Mininet CLI:


    iperf h1 h3


## Files

> staticnr/mininet_setup_staticnr.py

![4h_3s_topo](https://lh3.googleusercontent.com/hShnqz5EBqe0al-Dtiq80lbNsOayPyCPO4VFzSFmGCZ14eHqNsGnv6jdfQsMdJiYSHrA5uS4_NM_ "topo1")

 1. Setups up topology 4h_3s (shown above) 
 2. Starts two iperf servers at h3 on ports 4000 and  5000
 3. Creates three queues in s1 on interface eth3
	 -queue0: 500Mbit/s 
	 -queue1: 300Mbit/s
	 -queue2: 200Mbit/s 
 4. Starts iperf client on h1 to h3
 5. Starts iperf client on h2 to h3

> pox/ext/price_static.py

Provides static forwarding for the topology 4h_3s:

 - Forwards IP packets from h1 to h3 into a 300Mbit/s queue 
 - Forwards IP packets from h2 to h3 into a 200Mbit/s queue
 - Forwards all other IP packets without queue 
 - Floods all ARP packets
 
> staticr/mininet_setup_staticr.py

 1. Setups up topology 4h_3s
 2. Starts two iperf servers at h3 on ports 4000 and  5000
 3. Creates 12 queues in s1 (0-11). Three on each interface. i=2 for eth2 
	 -queue0+3i: 500Mbit/s 
	 -queue1+3i: 300Mbit/s
	 -queue2+3i: 200Mbit/s 
>pox/ext/price_static_requests.py

Provides static l3 forwarding for topology 4h_3s (same as price_static.py). However, it also runs POX messenger module and listens for messages on channel "qos". When it receives a message, it sends flow mod messages to s1 to provide QoS through improving bottleneck. 

>staticr/test_client.py

A utility for testing the request functionality in price_static_requests.py module. For now if you enter "test" it will send a JSON encoded request class to the controller on remote port 7790. On the server end the controller runs the POX messenger module and supports channel based communication. 

    class qosServiceRequest (object):
	    def __init__(self,ip1,ip2,level):
		    self.CHANNEL = "qos"
		    self.ip1 = ip1 
		    self.ip2 = ip2
		    self.level = level

ip1 and ip2 are the two IPs between which packets have a priority level. The lowest level is 0 and highest level is 2. 



