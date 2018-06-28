# Copyright 2013 <Your Name Here>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A skeleton POX component

You can customize this to do whatever you like.  Don't forget to
adjust the Copyright above, and to delete the Apache license if you
don't want to release under Apache (but consider doing so!).

Rename this file to whatever you like, .e.g., mycomponent.py.  You can
then invoke it with "./pox.py mycomponent" if you leave it in the
ext/ directory.

Implement a launch() function (as shown below) which accepts commandline
arguments and starts off your component (e.g., by listening to events).

Edit this docstring and your launch function's docstring.  These will
show up when used with the help component ("./pox.py help --mycomponent").
"""

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

# Create a logger for this component
log = core.getLogger()    

class PriceStaticRequestsController(object):
  """docstring for PriceStaticRequestsController"""
  def __init__(self):
    self.services = {} #ip pairing to service level 
    self.servicesLock = False #updateAllFlows accesses services on a timer so I'm gonna put a lock on it
    #self.services = {("10.0.0.1","10.0.0.3"): 2}

    self.connections = {} #switch to connection mapping eg.'s1'
    
    core.openflow.addListeners(self)
    core.listen_to_dependencies(self)

    Timer(1,self.updateAllFlows,recurring=True) #update all flows every second

  def _all_dependencies_met(self):
    qos_channel = core.MessengerNexus.get_channel("qos")
    def handle_qos_message(event,msg):
      ip1 = str(msg.get("ip1"))
      ip2 = str(msg.get("ip2"))
      level = str(msg.get("level"))

      print "ip1: ", ip1
      print "ip2: ", ip2
      print "level: ", level

      servicesLock = True
      self.services[(ip1,ip2)] = level
      servicesLock = False

    qos_channel.addListener(MessageReceived, handle_qos_message)


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

  def updateAllFlows(self):
    if self.servicesLock != True:
      print "hello"
      for k,v in self.connections.items():
        v.updateFlows(self.services)


class PriceStaticRequestsSwitch(object):
  """docstring for PriceStaticSwitch"""
  def __init__(self,connection,identifier):
    self.connection = connection
    self.arpTable = {} #useless for static 
    self.identifier = identifier #eg "s1" or "s2"
    self.ipToPort = {} #used for static l3 forwarding
    self.initialized = False #initStaticRoute will run once at the start and put all IP packets into lowest priority queue. timeouts are 0 so using a initialized flag so QoS flows don't get overwritten

    #static IP fowarding table
    #see diagram 4h_3s in README.md
    if identifier == "s1":
      self.ipToPort["10.0.0.1"] = 1
      self.ipToPort["10.0.0.2"] = 2
      self.ipToPort["10.0.0.3"] = 3
      self.ipToPort["10.0.0.4"] = 4
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

  def getQueueId(self,port,level):
    #there are three queues on each interface
    #eth1  eth 2  eth 3 eth 4
    #0,1,2 3,4,5, 6,7,8 9,10,11
    #eth1:
    #level 2 is queue 0 (highest bandwidth)
    #level 1 is queue 1 
    #level 0 is queue 2 (lowest bandwidth) default queue
    #eth2:
    #level 2 is queue 3 (highest bandwdith)
    #level 1 is queue 4
    #level 0 is queue 5 (lowest bandwidth) default queue

    #for level l and port p
    #queue = 3(p-1) + (2-l)
    return (port-1)*3 + (2-int(level))

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
            self.enqueue(10,0,0,0x0800,ip1,self.ipToPort[ip1],self.getQueueId(self.ipToPort[ip1],0),ip2)
        # self.enqueue(100,0,0,0x0800,"10.0.0.1",self.ipToPort["10.0.0.1"],2)
        # self.enqueue(100,0,0,0x0800,"10.0.0.2",self.ipToPort["10.0.0.2"],5)
        # self.enqueue(100,0,0,0x0800,"10.0.0.3",self.ipToPort["10.0.0.3"],8)
        # self.enqueue(100,0,0,0x0800,"10.0.0.4",self.ipToPort["10.0.0.4"],11)

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
        ip1 = k[0]
        ip2 = k[1]
        level = v

        print ("enqueue src:", ip1, " dst:", ip2, " port:", self.ipToPort[ip2], " queueid:", (self.getQueueId(self.ipToPort[ip2],level)))
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


