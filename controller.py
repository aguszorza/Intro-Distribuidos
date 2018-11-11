
# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.packet as pkt
from pox.lib.revent import *                  # Event library
import pox.lib.recoco as recoco               # Multitasking library
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer
import time
from pox.host_tracker import host_tracker

# Create a logger for this component
log = core.getLogger()

class MyController(EventMixin):

    def __init__ (self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        #Flood multicast packets => arp
        print "Flooding multicast packets in switch: " + dpidToStr(event.connection.dpid)
        msg = of.ofp_flow_mod()
        msg.match.dl_dst = EthAddr("ff:ff:ff:ff:ff:ff")
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)


    def _handle_PacketIn(self, event):
        """ Packet processing """
        packet = event.parsed
        dpid = event.connection.dpid

        def flood():
            #Flood incoming packet if dst is not known yet
            #Do not update flow table
            print "Flooding packet in switch: " + dpidToStr(event.connection.dpid) + " --- dst=" + str(packet.find(pkt.ethernet).dst)
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        ip6_packet = packet.find(pkt.ipv6)
        if ip6_packet is not None:
            return

        dst = core.host_tracker.getMacEntry(packet.find(pkt.ethernet).dst)
        if dst is None:
            return flood()

        print "Calculating packet path in switch: " + dpidToStr(event.connection.dpid) + " --- dst=" + str(packet.find(pkt.ethernet).dst)
        #print dpidToStr(event.connection.dpid)
        for adjacency in core.openflow_discovery.adjacency:
            if adjacency.dpid1 == dpid:
                pass
        return

        eth_packet = packet.find(pkt.ethernet)
        if eth_packet is not None:
            src_mac = eth_packet.src
            dst_mac = eth_packet.dst
            print "ETHERNET: src=" + str(src_mac) + " dst=" + str(dst_mac)

        ip_packet = packet.find(pkt.ipv4)
        if ip_packet is not None:
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip
            print "IP: src=" + str(src_ip) + " dst=" + str(dst_ip)

        tcp_packet = packet.find(pkt.tcp)
        if tcp_packet is not None:
            src_port = tcp_packet.srcport
            dst_port = tcp_packet.dstport
            print "TCP: src=" + str(src_port) + " dst=" + str(dst_port)




def launch ():
    import pox.log.color
    pox.log.color.launch()
    import pox.log
    pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
    import pox.log.level
    import logging
    pox.log.level.launch(packet=logging.WARN, host_tracker=logging.INFO)

    from pox.core import core
    import pox.openflow.discovery
    pox.openflow.discovery.launch()

    core.registerNew(MyController)

    import pox.openflow.spanning_tree
    pox.openflow.spanning_tree.launch()

    import pox.host_tracker
    pox.host_tracker.launch()