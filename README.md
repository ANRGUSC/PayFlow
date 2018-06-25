# SDN Payments
SDN Payments is a forwarding system that provides QoS (Quality of Service) to hosts based on a payments system. It uses the POX controller and OpenVSwitch for switches. 

## Dependencies

 1. Mininet (2.2.2 confirmed working) 
 2. OpenVSwitch (2.9.0 confirmed working)

## Files

> mininet_setup.py

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





