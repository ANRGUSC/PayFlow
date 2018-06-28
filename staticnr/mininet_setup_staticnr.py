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
                          'price_static' ),
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

#create three queues on s1-eth3 (links s1 with s2)
#queue0 rate: 500000000
#queue1 rate: 300000000
#queue2 rate: 200000000
os.system('sudo ovs-vsctl -- set Port s1-eth3 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2 -- --id=@q0 create Queue other-config:min-rate=500000000 other-config:max-rate=500000000 -- --id=@q1 create Queue other-config:min-rate=300000000 other-config:max-rate=300000000 -- --id=@q2 create Queue other-config:min-rate=200000000 other-config:max-rate=200000000')
	
print("Testing bandwidth between h1 and h3")
clientBandwidthTest(h1,4000,'10.0.0.3')

print("Testing bandwidth between h2 and h3")
clientBandwidthTest(h2,4000,'10.0.0.3')

net.stop()
