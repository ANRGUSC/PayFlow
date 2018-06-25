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

# Create a logger for this component
log = core.getLogger()


class StaticPriceSwitch(object):
  """docstring for ClassName"""
  #static forwarding for network below:
  # h1    s2-h3
  #   \  /
  #    s1
  #   /  \
  # h2    s3-h4
  def __init__(self,connection,s1,s2,s3):

    #add switch as listener to connection events
    connection.addListeners(self)

    self._s1_dpid = s1
    self._s2_dpid = s2
    self._s3_dpid = s3
    self._connection = connection

  def _handle_PacketIn (self,event):

    def flood(_priority,_idle,_hard,_classifier):
      msg = of.ofp_flow_mod()
      msg.priority = _priority
      msg.idle_timeout = _idle 
      msg.hard_timeout = _hard
      msg.match.dl_type = _classifier
      msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))  
      self._connection.send(msg)

    def enqueue(_priority,_idle,_hard,_classifier,_src,_dst,_port,_queue):
      msg = of.ofp_flow_mod()
      msg.priority = _priority
      msg.idle_timeout = _idle
      msg.hard_timeout = _hard
      msg.match.dl_type = _classifier
      msg.match.nw_src = _src
      msg.match.nw_dst = _dst
      msg.actions.append(of.ofp_action_enqueue(port = _port, queue_id=_queue))
      self._connection.send(msg)

    def output(_priority,_idle,_hard,_classifier,_dst,_port):
      msg = of.ofp_flow_mod()
      msg.priority = _priority
      msg.idle_timeout = _idle
      msg.hard_timeout = _hard
      msg.match.dl_type = _classifier
      msg.match.nw_dst = _dst
      msg.actions.append(of.ofp_action_output(port = _port))
      self._connection.send(msg)

    if(self._connection.dpid == self._s1_dpid):
      #flood all ARPs 
      flood(1,0,0,0x0806)

      #enqueue IP packets from h1 to h3 in queue1 (eth3)
      enqueue(100,0,0,0x0800,"10.0.0.1","10.0.0.3",3,1)
      #enqueue IP packet from h2 to h3 in queue2 (eth3)
      enqueue(100,0,0,0x0800,"10.0.0.2","10.0.0.3",3,2)

      #output IP packets to h4 on port4 (eth4)
      output(10,0,0,0x0800,"10.0.0.4",4)

      #output IP packets to h1 on port1 (eth1)
      output(10,0,0,0x0800,"10.0.0.1",1)
      #output IP packets to h2 on port2 (eth2)
      output(10,0,0,0x0800,"10.0.0.2",2)


    elif(self._connection.dpid == self._s2_dpid):
      #flood all ARPs
      flood(1,0,0,0x0806)

      #output IP packets to h3 on port2 (eth2)
      output(10,0,0,0x0800,"10.0.0.3",2)

      #output IP packets to h1,h2 and h4 on port1 (eth1)
      output(10,0,0,0x0800,"10.0.0.1",1)
      output(10,0,0,0x0800,"10.0.0.2",1)
      output(10,0,0,0x0800,"10.0.0.4",1)

    elif(self._connection.dpid == self._s3_dpid):
      #flood all ARPs
      flood(1,0,0,0x0806)

      #output IP packets to h4 on port2 (eth2)
      output(10,0,0,0x0800,"10.0.0.4",2)

      #output IP packets to h1,h2 and h3 on port1 (eth1)
      output(10,0,0,0x0800,"10.0.0.1",1)
      output(10,0,0,0x0800,"10.0.0.2",1)
      output(10,0,0,0x0800,"10.0.0.3",1)




class PriceStatic(object):
  """docstring for PriceStatic"""
  #forwards packets coming from h1 to h3 into queue1 and h2 to h3 into queue2
  def __init__(self):
    core.openflow.addListeners(self)
    self.s1_dpid = 0
    self.s2_dpid = 0
    self.s3_dpid = 0

  def _handle_ConnectionUp(self,event):
    for port in event.connection.features.ports:
      if ((port.name == "s1-eth1") or (port.name == "s1-eth2") or (port.name == "s1-eth3") or (port.name == "s1-eth4")):
        self.s1_dpid = event.connection.dpid
        print "s1_dpid=",self.s1_dpid
      elif ((port.name == "s2-eth1") or (port.name == "s2-eth2")):
        self.s2_dpid = event.connection.dpid
        print "s2_dpid=",self.s2_dpid
      elif ((port.name == "s3-eth1") or (port.name == "s3-eth2")):
        self.s3_dpid = event.connection.dpid
        print "s3_dpid=",self.s3_dpid
    StaticPriceSwitch(event.connection,self.s1_dpid,self.s2_dpid,self.s3_dpid)
    


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

  core.registerNew(PriceStatic)


