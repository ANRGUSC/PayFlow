from mininet.topo import Topo

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

topos = { 'mytopo': ( lambda: ANRGTopo() ) }