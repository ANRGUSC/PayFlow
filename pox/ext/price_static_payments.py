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

from pox.messenger import *                   # Messenger library
from pox.lib.recoco import Timer              # Timer library 

import threading                              # Threading library
import socket                                 # Socket library
import json                                   # JSON library
import os

from iota import Iota                         # IOTA library

import Crypto.Hash.MD5 as MD5
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES

# Create a logger for this component
log = core.getLogger()    

class ServiceChanged(revent.Event):
  """Event raised by qosBroker when there is a change in service levels. 

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


class qosBroker(revent.EventMixin):
  """Class that handles all QoS payments 
  

  """
  _eventMixin_events = set([
    ServiceChanged,
    ])
  def __init__(self,port):
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

  def sendMenu(self,conn):
    json_string = self.prepareMenuData('../staticp/menu.json') 
    conn.send(json_string) #send MENU message to client



class PriceStaticRequestsController(object):
  """Class that represents the controller in the SDN architecture

  """
  def __init__(self):
    self.services = {} #ip pairing to service level 
    self.servicesMutex = threading.Lock() 
    #self.services = {("10.0.0.1","10.0.0.3"): 2}
    self.connections = {} #switch to connection mapping eg.'s1'
    self.broker = qosBroker(6113)

    self.broker.addListeners(self)
    core.openflow.addListeners(self)

  def _handle_ConnectionUp(self,event):
    for port in event.connection.features.ports:
      if ((port.name == "s1-eth1") or (port.name == "s1-eth2") or (port.name == "s1-eth3") or (port.name == "s1-eth4")):
        switch = "s1"
      elif ((port.name == "s2-eth1") or (port.name == "s2-eth2")):
        switch = "s2"
      elif ((port.name == "s3-eth1") or (port.name == "s3-eth2")):
        switch = "s3"
      else:
        switch = "unknown switch"
    print "connection from", switch
    self.connections[switch] = PriceStaticRequestsSwitch(event.connection,switch)
    #PriceStaticRequestsSwitch(event.connection,switch)

  def _handle_ServiceChanged(self,event):
    #print "ip1:" + event.ip1 + " ip2:" + event.ip2 + " level:" + event.level + " op:" + event.opcode
    if event.opcode == "ADD":
      self.services[(event.ip1,event.ip2)] = int(event.level[5])
    elif event.opcode == "REMOVE":
      self.services[(event.ip1,event.ip2)].remove()
      
    self.updateAllFlows()

  def updateAllFlows(self):
    self.servicesMutex.acquire()
    for k,v in self.connections.items():
      v.updateFlows(self.services)
    self.servicesMutex.release()



class PriceStaticRequestsSwitch(object):
  """Class that represents indivisual switches on the SDN. Instantiated once when a switch is discovered.

  """
  def __init__(self,connection,identifier):
    self.connection = connection
    self.arpTable = {} #useless for static 
    self.identifier = identifier #eg "s1" or "s2"
    self.ipToPort = {} #used for static l3 forwarding
    self.initialized = False #initStaticRoute will run once at the start and put all IP packets into lowest priority queue. timeouts are 0 so using a initialized flag so QoS flows don't get overwritten
    self.unusedQueues = {} #stack 

    #static IP fowarding table
    #see diagram 4h_3s in README.md
    if identifier == "s1":
      self.ipToPort["10.0.0.1"] = 1
      self.ipToPort["10.0.0.2"] = 2
      self.ipToPort["10.0.0.3"] = 3
      self.ipToPort["10.0.0.4"] = 4
      for interface in {'eth1','eth2','eth3'}:
        for level in {1,2,3}:
          self.unusedQueues[(interface,level)] = [0,1]

    elif identifier == "s2":
      self.ipToPort["10.0.0.1"] = 1
      self.ipToPort["10.0.0.2"] = 1
      self.ipToPort["10.0.0.3"] = 2
      self.ipToPort["10.0.0.4"] = 1
    elif identifier == "s3": 
      self.ipToPort["10.0.0.1"] = 1
      self.ipToPort["10.0.0.2"] = 1
      self.ipToPort["10.0.0.3"] = 1
      self.ipToPort["10.0.0.4"] = 2

    connection.addListeners(self)


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

  def initStaticRoute(self):
    if self.initialized == False:
      if(self.identifier == "s1"):
        #flood all ARPs 
        self.flood(1,0,0,0x0806)

        #enqueue packets from all hosts into default queue on respective interfaces
        #queue are setup in mininet_setup_staticr.py
        #there are 3 queues per interface. default queue is the last one
        #eth1 queue ids: 0,1,2
        #eth2 queue ids: 3,4,5
        #eth3 queue ids: 6,7,8
        #eth4 queue ids: 9,10,11
        ips = ["10.0.0.1","10.0.0.2","10.0.0.3","10.0.0.4"]

        for ip1 in ips:
          for ip2 in ips:
            if ip1 is not ip2:
              self.enqueue(10,0,0,0x0800,ip1,self.ipToPort[ip1],self.getQueueId(self.ipToPort[ip1],0),ip2)
              print "ip1:" + ip1 + " ip2:" + ip2 
              print "queueid:" + str(self.getQueueId(self.ipToPort[ip1],0))

        self.initialized = True

        print "s1"

      elif(self.identifier == "s2"):
        #flood all ARPs
        self.flood(1,0,0,0x0806)

        #output IP packets to h3 on port2 (eth2)
        self.output(10,0,0,0x0800,"10.0.0.3",self.ipToPort["10.0.0.3"])

        #output IP packets to h1,h2 and h4 on port1 (eth1)
        self.output(10,0,0,0x0800,"10.0.0.1",self.ipToPort["10.0.0.1"])
        self.output(10,0,0,0x0800,"10.0.0.2",self.ipToPort["10.0.0.2"])
        self.output(10,0,0,0x0800,"10.0.0.4",self.ipToPort["10.0.0.4"])

        self.initialized = True

        print "s2"

      elif(self.identifier == "s3"):
        #flood all ARPs
        self.flood(1,0,0,0x0806)

        #output IP packets to h4 on port2 (eth2)
        self.output(10,0,0,0x0800,"10.0.0.4",self.ipToPort["10.0.0.4"])

        #output IP packets to h1,h2 and h3 on port1 (eth1)
        self.output(10,0,0,0x0800,"10.0.0.1",self.ipToPort["10.0.0.1"])
        self.output(10,0,0,0x0800,"10.0.0.2",self.ipToPort["10.0.0.2"])
        self.output(10,0,0,0x0800,"10.0.0.3",self.ipToPort["10.0.0.3"])

        self.initialized = True

        print "s3"
      else:
        print "wtf"


  def _handle_PacketIn(self,event):
    #enqueue all IP packets into default queue (queue2) to start
    #floop all APR
    self.initStaticRoute()

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

  core.registerNew(PriceStaticRequestsController)  


