#!/bin/sh

sudo fuser -k 6653/tcp #openflow
sudo fuser -k 6633/tcp #openflow
sudo fuser -k 7790/tcp #messenger

sudo mn -c #mininet

case $1 in
	staticnr )
		sudo python staticnr/mininet_setup_staticnr.py
		;;
	staticr )
		sudo python staticr/mininet_setup_staticr.py
		;;
	staticp )
		sudo python staticp/mininet_setup_staticp.py
		;;
	dev )
		# gnome-terminal --working-directory=$PWD -e "sudo mn --controller remote,ip=127.0.0.1 --custom topo.py --topo mytopo"
		# sudo python dynamicp/queue_setup.py
		# gnome-terminal --working-directory=$PWD -e "sudo python pox/pox.py price_dynamic_payments"
		;;
	*)
		echo Invalid option
		echo Available options:
		echo staticnr: static forwarding with no requests 
		echo staticr: static forwarding with requests for QoS
		echo dynamicr: dynamic l2 forwarding with requests for QoS
		;;
esac