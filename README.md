# SDN Payments
SDN Payments is a forwarding system that provides QoS (Quality of Service) to hosts based on a payments system. It uses the POX controller and OpenVSwitch for switches. 

## Dependencies
Mininet (2.2.2 confirmed working)
OpenVSwitch (2.9.0 confirmed working)

## Files

> pox/ext/price_static.py

Provides static forwarding for the topology shown below:
![4h_3s_topo](https://lh3.googleusercontent.com/hShnqz5EBqe0al-Dtiq80lbNsOayPyCPO4VFzSFmGCZ14eHqNsGnv6jdfQsMdJiYSHrA5uS4_NM_ "topo1")
 - Forwards IP packets from h1 to h3 into a 300Mbit/s queue 
 - Forwards IP packets from h2 to h3 into a 200Mbit/s queue
 - Forwards all other IP packets without queue 
 - Floods all ARP packets

