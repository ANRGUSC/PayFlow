from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Controller
from mininet.link import TCLink
from mininet.node import CPULimitedHost
from mininet.cli import CLI

import os

POXDIR = os.getcwd() + '/pox'

class POX( Controller ):
    def __init__( self, name, cdir=POXDIR,
                  command='python pox.py',
                  cargs=( 'openflow.of_01 --port=%s '
                          'price_dynamic_payments openflow.discovery host_tracker' ),
                  **kwargs ):
        Controller.__init__( self, name, cdir=cdir,
                             command=command,
                             cargs=cargs, **kwargs )

controllers={ 'pox': POX }

#	h1	  s2-h3
#	  \	 /
#	   s1
#	  /	 \
#	h2    s3-h4
class ANRGTopo( Topo ):
	"QOS Testing Topology"

	def __init__( self ):
		"Create custom topo."

		Topo.__init__( self )

		h1 = self.addHost('h1')
		h2 = self.addHost('h2')
		h3 = self.addHost('h3')
		h4 = self.addHost('h4')

		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')
		s3 = self.addSwitch('s3')

		self.addLink(h1,s1)
		self.addLink(h2,s1)

		self.addLink(s1,s2)
		self.addLink(s1,s3)

		#self.addLink(s2,h3,bw=5,delay='5ms',loss=1,max_queue_size=1000,use_htb=True)
		self.addLink(s2,h3)
		self.addLink(s3,h4)

#topos = { 'mytopo': ( lambda: ANRGTopo() ) }

def clientBandwidthTest(client,serverPort,serverIP):
	print client.cmd('iperf -c %s -p %d' %(serverIP,serverPort))

#create toplogy 
mytopo = ANRGTopo()
net = Mininet(topo=ANRGTopo(), controller=POX, link=TCLink)

#start network
net.start()

h1 = net.hosts[0]
h2 = net.hosts[1]
h3 = net.hosts[2]
h4 = net.hosts[3]

print h3.cmd('iperf -s -p 4000 &')
print h3.cmd('iperf -s -p 5000 &')

#create six queues on each interface (eth1 -> eth4)
#queue0-1 rate: 250000000
#queue2-3 rate: 150000000
#queue4-5 rate: 100000000
#queue6 rate: 50000000

os.system('sudo ovs-vsctl -- set Port s1-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s1-eth2 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=7=@q0,8=@q1,9=@q2,10=@q3,11=@q4,12=@q5,13=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s1-eth3 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=14=@q0,15=@q1,16=@q2,17=@q3,18=@q4,19=@q5,20=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s1-eth4 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=21=@q0,22=@q1,23=@q2,24=@q3,25=@q4,26=@q5,27=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000  -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')


os.system('sudo ovs-vsctl -- set Port s2-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s2-eth2 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=7=@q0,8=@q1,9=@q2,10=@q3,11=@q4,12=@q5,13=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
	
os.system('sudo ovs-vsctl -- set Port s3-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s3-eth2 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=7=@q0,8=@q1,9=@q2,10=@q3,11=@q4,12=@q5,13=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')



CLI(net)

net.stop()
