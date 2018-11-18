# Copyright (c) 2018, Autonomous Networks Research Group. All rights reserved.
#     Contributors: David Chen, Rahul Radhakrishnan
#     Read license file in main directory for more details  

# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

from pox.messenger import *                   # Messenger library
from pox.lib.recoco import Timer              # Timer library 
from pox.lib.packet.ipv4 import ipv4
from pox.host_tracker import host_tracker     # Host tracking library
from pox.openflow.discovery import Discovery

import threading                              # Threading library
import socket                                 # Socket library
import json                                   # JSON library
import os
import time
from sets import Set
import heapq

from iota import Iota                         # IOTA library

import Crypto.Hash.MD5 as MD5
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES


ARP_TIMEOUT = 60*2

levelToCapacity = {'level0': 50000000,
                   'level1': 100000000,
                   'level2': 150000000,
                   'level3': 250000000
                  }

# Create a logger for this component
log = core.getLogger()    

class ServiceChanged(revent.Event):
  """Event raised by QosBroker when there is a change in service levels. 

    Opcodes:
      ADD - add a service between ip1 and ip2
      REMOVE - remove the service between ip1 and ip2 

  """
  def __init__(self,ip1,ip2,level,opcode):
    revent.Event.__init__(self)
    self.ip1 = ip1
    self.ip2 = ip2
    self.level = level
    self.opcode = opcode

class ArpEntry(object):
  """Copyright 2011 James McCauley
  """
  def __init__(self,port,mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac
  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    return time.time() > self.timeout


class Queue(object):
  def __init__(self,queue_id,capacity):
    self.id = queue_id
    self.capacity = capacity

class QosBroker(revent.EventMixin):
  """Class that handles all QoS payments 
  

  """
  _eventMixin_events = set([
    ServiceChanged,
    ])
  def __init__(self,port,controller):
    self.controller = controller
    self.controller.addListeners(self)

    client = 'http://node02.iotatoken.nl:14265' #Look on www.iotatoken.nl for downtime announcements and real time info
    seed = ''
    #initialize IOTA API
    self.api = Iota(client, seed)
    #create new wallet and get it's address
    self.wallet = self.api.get_new_addresses(count=1)
    self.wallet = str(self.wallet['addresses'][0].address)

    self.signature_required = 1
    self.privateKey = RSA.generate(2048)
    self.publicKey = self.privateKey.publickey().exportKey('OpenSSH')

    #start server
    self.serverSocket = self.startServer(port)

  def clientThread(self,conn):
    #wait for HELLO message
    helloReceived = False
    while not helloReceived:
      message_json = json.loads(conn.recv(2048))
      if message_json['message_type'] == 'HELLO':
        print json.dumps(message_json,sort_keys=True, indent=4, separators=(',',':'))
        helloReceived = True

    #send MENU message
    self.sendMenu(conn)

    #receive ORDER message
    message_json = json.loads(conn.recv(2048))
    print json.dumps(message_json,sort_keys=True, indent=4, separators=(',',':'))

    if(message_json['message_type'] == 'PREORDER'):
      print "GOT PREORDER"
      preorder = message_json['data']
      preorder = json.loads(preorder)
      level = preorder['level']
      ip1 = preorder['ip1']
      ip2 = preorder['ip2'] 

      result = self.controller.preorder(ip1,ip2,level)

      print "PREORDER RESULT: " + str(result)

      if(result):
        self.sendPreorderResponse(conn,"TRUE")
      else:
        self.sendPreorderResponse(conn,"FALSE")





    elif(message_json['message_type'] == 'ORDER'):
      print "GOT ORDER"
      #read ORDER and verify on IOTA network that client payed (optional)
      payment_id = message_json['verification']
      signature = message_json['signature']
      order = message_json['data']
      order = json.loads(order)
      level = order['level']
      buyer_address = order['address']
      buyer_key = order['public-key']
      ip1 = order['ip1']
      ip2 = order['ip2']

      #skipping verification for now

      #raise event ServiceChanged (controller listens)  
      if 'time' in order:
        time = order['time']
        self.raiseEvent(ServiceChanged(ip1,ip2,level,"ADD"))
        Timer(int(time),self.raiseEvent,args=[ServiceChanged(ip1,ip2,level,"REMOVE")]) 

      else:
        self.raiseEvent(ServiceChanged(ip1,ip2,level,"ADD"))

  def serverThread(self,server):
    while True:
      client,addr = server.accept()

      t = threading.Thread(target=self.clientThread,args=(client,))
      t.start()

    
  def startServer(self,port):
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind(('',port)) 
    server.listen(50) #maximum concurrent clients

    #start serverThread
    t = threading.Thread(target=self.serverThread,args=(server,))
    t.start()  

    return(server)

  def signData(self,plaintext):
    hash = MD5.new(plaintext).digest()
    signature = self.privateKey.sign(hash,'')
    return signature

  def prepareJSONString(self,message_type, data, signature=None, verification=None):
    """
   Prepares the JSON message format to be sent to the Buyer
   :param message_type: MENU/SESSION_KEY/DATA/DATA_INVOICE
   :param data: Corresponding data
   :param signature: Signed Data
   :param verification: Address or the transaction ID in Tangle/Blockchain
   :return: JSON dictionary 
    """
    json_data = {}

    json_data['message_type'] = message_type
    json_data['data'] = data

    if signature:
        json_data['signature'] = signature
    else:
        json_data['signature'] = ""
    if verification:
        json_data['verification'] = verification
    else:
        json_data['verification'] = ""

    return json.dumps(json_data)

  def prepareMenuData(self,file):
    with open(file) as menuFile:
      menu = menuFile.read()
      menu = json.loads(menu)

      menu['payment-address'] = self.wallet
      menu['signature-required'] = self.signature_required
      menu['broker-public-key'] = self.publicKey
      menu = json.dumps(menu)

    signature = self.signData(menu)
    return self.prepareJSONString("MENU",menu,signature)

  def preparePreorderResponse(self,result,file):
    with open(file) as preorderrFile:
      preorderr = preorderrFile.read()
      preorderr = json.loads(preorderr)

      preorderr['result'] = result
      preorderr = json.dumps(preorderr)
      signature = self.signData(preorderr)
      return self.prepareJSONString("PREORDERR",preorderr,signature)

  def sendMenu(self,conn):
    json_string = self.prepareMenuData('../dynamicp/menu.json') 
    conn.send(json_string) #send MENU message to client

  def sendPreorderResponse(self,conn,result):
    json_string = self.preparePreorderResponse(result,'../dynamicp/preorderr.json')
    conn.send(json_string)



class PriceDynamicRequestsController(revent.EventMixin):
  """Class that represents the controller in the SDN architecture

  """

  def __init__(self):
    def startup():
      self.services = {} #ip pairing to service level 
      self.servicesMutex = threading.Lock() 
      #self.services = {("10.0.0.1","10.0.0.3"): 2}
      self.connections = {} #switch name to switch object mapping eg.'s1'
      self.dpidToSwitch = {} #switch dpid to switch object mapping 
      self.hostMACToSwitchDpid = {}
      self.arpTable = {} #ip to mac of known hosts 

      self.broker = QosBroker(6113,self)

      self.broker.addListeners(self)

      core.host_tracker.addListeners(self)
      core.openflow_discovery.addListeners(self)
      core.openflow.addListeners(self)
    core.call_when_ready(startup,('openflow','openflow_discovery','host_tracker'))

  def _handle_HostEvent (self, event):
    #raised when there is a host that JOINed MOVEd or LEAVEs the network
    # if(event.join or event.move):
    #   print event.entry
    #   self.hostMACToSwitchDpid[event.entry.macaddr] = event.entry.dpid

    if(event.join or event.move):
      print event.entry
      self.hostMACToSwitchDpid[str(event.entry.macaddr)] = int(event.entry.dpid)
    elif(event.leave):
      del self.hostMACToSwitchDpid[str(event.entry.macaddr)]
  def _handle_ConnectionUp(self,event):
    ports = [] #ports that the connected switch has
    for port in event.connection.features.ports:
      ports.append(port.name)

    switch = ports[0] #the first port is always the name of the switch itself


    ports = [(p.port_no, p.hw_addr) for p in event.ofp.ports]

    self.connections[switch] = PriceDynamicPaymentsSwitch(event.connection,switch,event.dpid,ports,self)
    self.dpidToSwitch[int(event.dpid)] = self.connections[switch]


  def _handle_ServiceChanged(self,event):
    #print "ip1:" + event.ip1 + " ip2:" + event.ip2 + " level:" + event.level + " op:" + event.opcode
    if event.opcode == "ADD":
      self.services[(event.ip1,event.ip2)] = int(event.level[5])
    elif event.opcode == "REMOVE":
      #self.services[(event.ip1,event.ip2)].remove()
      self.services[(event.ip1,event.ip2)] = 0
      
    self.updateAllFlows()

  def preorder(self,ip1,ip2,level):
    print "handling preorder"

    print "IP ONE: " + str(ip1)
    print "IP TWO: " + str(ip2)

    if((ip1 not in self.arpTable) or (ip2 not in self.arpTable)):
      print "one of the PREORDER IP addresses is not in ARP Table"
      print self.arpTable
      return False

    mac1 = self.arpTable[ip1]
    mac2 = self.arpTable[ip2]

    if((mac1 not in self.hostMACToSwitchDpid) or (mac2 not in self.hostMACToSwitchDpid)):
      print "one of the PREORDER MAC addresses is not in the host discovery table"
      print self.hostMACToSwitchDpid
      return False

    endSwitch1Dpid = self.hostMACToSwitchDpid[mac1]
    endSwitch2Dpid = self.hostMACToSwitchDpid[mac2]

    print "IMPORTANTTTTTT:"
    print "mac ONE: " + str(mac1)
    print "mac TWO: " + str(mac2)
    print "SWITCH ATTACHED TO MAC ONE DPID:" + str(endSwitch1Dpid)
    print "SWITCH ATTACHED TO MAC TWO DPID:" + str(endSwitch2Dpid)
    print "END"

    return self.RunRouteSearch(endSwitch1Dpid,endSwitch2Dpid,levelToCapacity[level])


  def RunRouteSearch(self,s1dpid,s2dpid,capacity):
    #return true or false 
    #DFS

    #self.dpidToSwitch[s1dpid].adjacent[port] => list of tuples (neighbour switch dpid, neighbour switch port)

    for k,v in self.dpidToSwitch.items(): 
      print "dpid:" + str(k)
      print "adjacent:" 
      print v.adjacent
     

    visited = Set([s1dpid])
    

    return self.RunRouteSearchHelper(s1dpid,s2dpid,visited,capacity)

  def RunRouteSearchHelper(self,currentDpid,endDpid,visited,capacity):
    if(currentDpid == endDpid):
      return True

    currentSwitch = self.dpidToSwitch[currentDpid]
    found = False
    for port,links in currentSwitch.adjacent.items():
      for link in links:
        if link[0] not in visited:
          visited.add(link[0])  
          if (currentSwitch.hasQueueWithCapacity(port,capacity)) and (self.dpidToSwitch[link[0]].hasQueueWithCapacity(link[1],capacity)):
            found = found or self.RunRouteSearchHelper(link[0],endDpid,visited,capacity)

    return found

  def updateAllFlows(self):
    self.servicesMutex.acquire()
    for k,v in self.connections.items():
      v.updateFlows(self.services)
    self.servicesMutex.release()

  def _handle_LinkEvent(self,event):
    link = event.link
    dpid1 = link.dpid1 #int
    dpid2 = link.dpid2
    port1 = link.port1
    port2 = link.port2

    print "dpid1:" + str(dpid1)
    print "dpid2:" + str(dpid2)
    print "port1" + str(port1)
    print "port2" + str(port2)

    if(port1 not in self.dpidToSwitch[dpid1].adjacent):
      self.dpidToSwitch[dpid1].adjacent[port1] = []
    if(port2 not in self.dpidToSwitch[dpid2].adjacent):
      self.dpidToSwitch[dpid2].adjacent[port2] = []

    #do not append both directions because other direction will have a corresponding LinkEvent
    self.dpidToSwitch[dpid1].adjacent[port1].append((dpid2,port2))



class PriceDynamicPaymentsSwitch(object):
  """Class that represents indivisual switches on the SDN. Instantiated once when a switch is discovered.

  """
  def __init__(self,connection,identifier,dpid,ports,controller):
    self.connection = connection
    self.adjacent = {}
    self.identifier = identifier #eg "s1" or "s2"
    self.forwardingTable = {}
    self.dpid = dpid 
    self.ports = ports #tuple that contains (port_num, port_addr)
    self.discoveryPackets = {}
    self.portsToUnusedQueues = {}
    self.controller = controller


    connection.addListeners(self)

    for port_num, port_addr in self.ports:
      self.adjacent[int(port_num)] = []

      #2.Create a list of queues for all ports
      self.portsToUnusedQueues[port_num] = {}

      #STATIC FOR NOW. SHOULD FILL USING DATA FROM OPENVSWITCHDB 
      #STATIC QUEUES:
      #q0,q1: level3 = 250MBit/s
      #q2,q3: level2 = 150MBit/s
      #q4,q5: level1 = 100MBit/s
      #q6: level0 = 50MBit/s
      queues = [(0,250000000),(1,250000000),(2,150000000),(3,150000000),(4,100000000),(5,100000000),(6,50000000)]
      for queue_id, queue_capacity in queues:
        if(queue_capacity not in self.portsToUnusedQueues[port_num]):
          self.portsToUnusedQueues[port_num][queue_capacity] = []
        self.portsToUnusedQueues[port_num][queue_capacity].append(Queue(queue_id,queue_capacity))  


  def hasQueueWithCapacity(self,port,capacity):
    if(capacity not in self.portsToUnusedQueues[port]):
      return False
    else:
      if(len(self.portsToUnusedQueues[port][capacity]) == 0):
        return False
      else:
        return True


  def flood(self,priority,idle,hard,classifier):
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.idle_timeout = idle 
    msg.hard_timeout = hard
    msg.match.dl_type = classifier
    msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))  
    self.connection.send(msg)

  def enqueue(self,priority,idle,hard,classifier,dstIP,port,queue,srcIP=None):
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.idle_timeout = idle
    msg.hard_timeout = hard
    msg.match.dl_type = classifier
    msg.match.nw_dst = dstIP
    if srcIP is not None:
      msg.match.nw_src = srcIP
    msg.actions.append(of.ofp_action_enqueue(port=port, queue_id=queue))
    self.connection.send(msg)

  def output(self,priority,idle,hard,classifier,dstIP,port):
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.idle_timeout = idle
    msg.hard_timeout = hard
    msg.match.dl_type = classifier
    msg.match.nw_dst = dstIP
    msg.actions.append(of.ofp_action_output(port=port))
    self.connection.send(msg)

  def enqueue_mac(self,priority,idle,hard,classifier,dstMAC,port,queue,srcMAC=None,data=None):
    msg = of.ofp_flow_mod()
    msg.data = data
    msg.priority = priority
    msg.idle_timeout = idle
    msg.hard_timeout = hard
    msg.match = of.ofp_match(dl_dst = dstMAC)
    msg.actions.append(of.ofp_action_enqueue(port=port, queue_id=queue))
    self.connection.send(msg)

  def output_mac(self,priority,idle,hard,classifier,dstMAC,port,data=None):
    msg = of.ofp_flow_mod()
    msg.data = data
    msg.priority = priority
    msg.idle_timeout = idle
    msg.hard_timeout = hard
    msg.match = of.ofp_match(dl_dst = dstMAC)
    msg.actions.append(of.ofp_action_output(port=port))
    self.connection.send(msg)

  def getQueueId(self,port,level,queueNumber=None):
    #there are seven queues on each interface on switch1
    #eth1           eth 2               eth 3                 eth 4
    #0,1,2,3,4,5,6  7,8,9,10,11,12,13   14,15,16 17,18,19,20  21,22,23,24,25,26,27
    #eth1:
    #level 3 are queues 0,1 (highest bandwidth)
    #level 2 are queues 2,3 
    #level 1 are queues 4,5
    #level 0 are queues 6 (lowest bandwidth) default queue
    #eth2:
    #level 3 are queues 7,8
    #level 2 are queues 9,10
    #level 1 are queues 11,12
    #level 0 are queues 13

    #currently there are two queues per level on each interface (statically set) so queue number can be 0 or 1 except for level0

    #for level l, port p and queue number n
    #queue = 7(p-1) + (6-2l) + n

    if (queueNumber == None) or (level == 0):
      queueNumber = 0

    return (port-1)*7 + (6-2*level) + queueNumber

  def updateFlows(self,services):
    #update flows based on QoS database (only s1 for now since it's the only one with queues)
    if(self.identifier == "s1"):
      #debugging purposes
      print("updating!")
      print("connection dpid=",self.connection.dpid)
      for k,v in services.items():
        #loop through all IP pairs in current QoS service database
        ip1 = str(k[0])
        ip2 = str(k[1])
        level = int(v)

        print ("enqueue src:", ip1, " dst:", ip2, " port:", self.ipToPort[ip2], " queueid:", self.getQueueId(self.ipToPort[ip2],level))
        self.enqueue(100,0,0,0x0800,ip2,self.ipToPort[ip2],(self.getQueueId(self.ipToPort[ip2],level)))
        print ("enqueue src:", ip2, " dst:", ip1, " port:", self.ipToPort[ip1], " queueid:", self.getQueueId(self.ipToPort[ip1],level) )
        self.enqueue(100,0,0,0x0800,ip1,self.ipToPort[ip1],(self.getQueueId(self.ipToPort[ip1],level)))

        del services[(ip1,ip2)]
    else: 
      print "not s1 so not updating!"

  def resend_packet (self, packet_in, out_port):
    log.debug("Resending Packet on requested port")
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_switch (self, event, packet, packet_in):

    # Learn the port for the source MAC
    # self.forwardingTable ... <add or update entry

    if packet.type == ethernet.LLDP_TYPE: # Ignore LLDP packets
      return
    #if it's not an IP or ARP packet, ignore
    #there were problems forwarding packets that discovery/host tracker module used 
    #caused hosts to "move" around the network because the packets are not being dropped
    #should probably check if it's a discovery packet, if so drop however doing this for now
    if (packet.type != packet.ARP_TYPE) and (packet.type != packet.IP_TYPE):
      return

    dpid = event.connection.dpid
    log.debug("Entering arp for DPID:")
    if dpid not in self.forwardingTable:
      # New switch -- create an empty table
      self.forwardingTable[dpid] = {}

    out_port = None
    if packet.src not in self.forwardingTable[dpid]:
      self.forwardingTable[dpid][packet.src] = packet_in.in_port
      log.debug("Added Entry into ARP:")

    
    if packet.type==packet.ARP_TYPE:
      a = packet.next
      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc not in self.controller.arpTable:
              self.controller.arpTable[str(a.protosrc)] = str(packet.src) 


    # print "ARP TABLE:"
    # print self.controller.arpTable
    # print "END OF ARP TABLE"  
      
    if packet.dst in self.forwardingTable[dpid]:
      out_port = self.forwardingTable[dpid][packet.dst]
    # if the port associated with the destination MAC of the packet is known:
    if out_port is not None:
      # Send packet out the associated port
      log.debug("Entry found in ARP...Unicasting")
      if self.identifier == "s1":
        self.enqueue_mac(10,0,0,0x0800,packet.dst,out_port,self.getQueueId(out_port,0),packet.src,packet_in)
      else:
        #self.resend_packet(packet_in,out_port)
        self.output_mac(10,0,0,0x0800,packet.dst,out_port,packet_in)

      """log.debug("Installing flow...")

      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match(dl_dst = packet.dst)
      msg.idle_timeout = 0
      msg.hard_timeout = 0
      action = of.ofp_action_output(port = out_port)
      msg.actions.append(action)

      self.connection.send(msg)"""

    else:
      # Flood the packet out everything but the input port
      log.debug("Flooding ARP")
      #self.flood(1,0,0,0x0806,packet_in)
      self.resend_packet(packet_in, of.OFPP_ALL)

  def _handle_PacketIn(self,event):
    #print "switch packet in "
    #enqueue all IP packets into default queue (queue2) to start
    #floop all ARP
    packet = event.parsed
    packet_in = event.ofp
    if not packet.parsed:
      log.warning("Ignoring unparsed packet")
      return
    self.act_like_switch(event, packet, packet_in)
    # self.initStaticRoute()





def _go_up (event):
  # Event handler called when POX goes into up state
  # (we actually listen to the event in launch() below)
  log.info("Skeleton application ready (to do nothing).")



@poxutil.eval_args
def launch ():
  """
  The default launcher just logs its arguments
  """
  # When your component is specified on the commandline, POX automatically
  # calls this function.

  # Add whatever parameters you want to this.  They will become
  # commandline arguments.  You can specify default values or not.
  # In this example, foo is required and bar is not.  You may also
  # specify a keyword arguments catch-all (e.g., **kwargs).

  # For example, you can execute this component as:
  # ./pox.py skeleton --foo=3 --bar=4

  # Note that arguments passed from the commandline are ordinarily
  # always strings, and it's up to you to validate and convert them.
  # The one exception is if a user specifies the parameter name but no
  # value (e.g., just "--foo").  In this case, it receives the actual
  # Python value True.
  # The @pox.util.eval_args decorator interprets them as if they are
  # Python literals.  Even things like --foo=[1,2,3] behave as expected.
  # Things that don't appear to be Python literals are left as strings.

  # If you want to be able to invoke the component multiple times, add
  # __INSTANCE__=None as the last parameter.  When multiply-invoked, it
  # will be passed a tuple with the following:
  # 1. The number of this instance (0...n-1)
  # 2. The total number of instances for this module
  # 3. True if this is the last instance, False otherwise
  # The last is just a comparison between #1 and #2, but is convenient.

  core.addListenerByName("UpEvent", _go_up)


  core.registerNew(PriceDynamicRequestsController)  



