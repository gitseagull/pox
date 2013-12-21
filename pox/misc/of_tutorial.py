# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's quite similar to the one for NOX.  Credit where credit due. :)
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.vlan import vlan
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.arp import arp

import time
import datetime

log = core.getLogger()

#Added by mzw. 2013.11.04
class Simples(object):
    def __init__(self):
      core.openflow.addListeners(self)
    def _handle_ConnectionUp(self,event):
      self._install(event.connection.dpid,1,(2,3))
      self._install(event.connection.dpid,2,(1,3))
      self._install(event.connection.dpid,3,(1,3))
      print event.connection.dpid
    def _install(self,switch,in_port,out_port):
      msg = of.ofp_flow_mod()
      match = of.ofp_match()
      match.in_port = in_port
      msg.match = match
      msg.idle_timeout = 0
      msg.hard_timeout = 0
      for i  in out_port:
        msg.actions.append(of.ofp_action_output(port = i))
        #msg.actions.append(of.ofp_action_output(port = out_port[i]))
      core.openflow.sendToDPID(switch,msg)


class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    # Use this table to keep track of which ip address is on
    # which ethernet address(keys are ip, values are MACs).
    self.ip_to_mac = {}

    #Added by mzw. 2013.11.03
    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.ip_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """



    #Added by mzw. 2013.11.04
    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        #msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      #elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        #msg.buffer_id = event.ofp.buffer_id
        #msg.in_port = event.port
        self.connection.send(msg)

    #self.macToPort[packet.src] = event.port # 1

    '''
    if not self.transparent: # 2
      #here
      print packet.type
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return
    '''
    ethernet_type = packet.getNameForType(packet.type)
    if ethernet_type == 'ARP' or ethernet_type == 'IP':
      #drop(3)
      if ethernet_type == 'IP' :
        print 'Start>>>>>>>>>'
        '''
        packet_ip= packet.next
        print packet_ip.protocol
        print packet_ip.srcip
        print packet_ip.dstip
        print packet_ip.ttl
        print packet_ip.tos
        print packet_ip.id
        '''
        #print dir(packet)
        print 'End>>>>>>>>>'


    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    #self.mac_to_port ... <add or update entry>
		#Added by mzw.
    if packet_in.in_port is not None:
				lport = packet_in.in_port
    #print packet.type
    lmac = packet.src

    self.mac_to_port[lmac] = lport
    #print 'MAC:', lmac.toStr(),'Port:',self.mac_to_port[lmac], 'Added OK',datetime.datetime.now()

    dmac = packet.dst.toStr()
    #print dmac,'Dest mac',datetime.datetime.now()

    #print packet.type()

    if self.mac_to_port.has_key(dmac):
			# Send packet out the associated port
      self.resend_packet(packet_in, self.mac_to_port[dmac])

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)
      msg.match.ofp_match.dl_dst = dmac
      msg.match.ofp_match.nw_dst = packet.next.nw_dst
      msg.out_port = self.mac_to_port[dmac]

      #self.connection.send(msg)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_FLOOD)

      #Added by mzw. 2013.11.5
      msg = of.ofp_flow_mod()
      msg.idle_timeout = 0
      msg.hard_timeout = 0
      #
      ## Set fields to match received packet
      #msg.match = of.ofp_match.from_packet(packet)
      msg.match.dl_src = lmac
      #msg.match.ofp_match.dl_dst = dmac
      #if isinstance(packet.next , ipv4):
      if packet.next == 0x0800:
        #msg.match.ofp_match.nw_dst = packet.next.dstip
        msg.match.ofp_match.nw_dst = "10.0.1.3"
        print 'IP'
      #if isinstance(packet.next , arp):
      if packet.next == 0x0806:
        #msg.match.ofp_match.nw_dst = packet.next.protodst
        print 'ARP'
        msg.match.ofp_match.nw_dst = "10.0.1.3"

      #self.connection.send(msg)

  #Added by mzw.
  def act_like_router(self, packet, packet_in):
    """
    Implement router-like behavior.
    """
    #MAC
    if packet_in.in_port is not None:
        lport = packet_in.in_port				
        packet_in.show
    lmac = packet.src
    #print 'mzw',lmac

    self.mac_to_port[lmac] = lport
    #print 'MAC:', lmac.toStr(),'Port:',self.mac_to_port[lmac], 'Added OK',datetime.datetime.now()

    dmac = packet.dst.toStr()
    #print dmac,'Dest mac',datetime.datetime.now()


    #print packet_in.dpid
    #ARP
    ethernet_type = packet.getNameForType(packet.type)
    print ethernet_type , packet.type
    if ethernet_type == 'ARP':
      packet_arp = packet.next
      print packet_arp._to_str()
      #print packet_arp.opcode
      print packet_arp.protosrc,'HeiHei' 
      self.ip_to_port[packet_arp.protosrc] = lport
      self.ip_to_mac[packet_arp.protosrc] = packet_arp.hwsrc
      '''
      if self.ip_to_mac.has_key(packet_arp.protodst):
        if self.mac_to_port.has_key(dmac):
            self.resend_packet(packet_in, self.mac_to_port[dmac])

    elif ethernet_type == 'IP':
      packet_ip = packet.next
      if self.ip_to_mac.has_key(packet_ip.protodst):
        if self.mac_to_port.has_key(dmac):
            self.resend_packet(packet_in, self.mac_to_port[dmac])
      '''

    if ethernet_type == 'IP':
      packet_ip= packet.next
      print packet_ip.protocol
      print packet_ip.srcip
      print packet_ip.dstip
      print packet_ip.ttl
      print packet_ip.tos
      print packet_ip.id


    if self.mac_to_port.has_key(dmac):
			# Send packet out the associated port
      self.resend_packet(packet_in, self.mac_to_port[dmac])

      #log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_FLOOD)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)
    #self.act_like_router(packet, packet_in)
    #print 'dpid',event.dpid



def launch ():
  """
  Starts the component
  """
  core.registerNew(Simples)
  '''
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
  '''
