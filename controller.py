
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
import random

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

        eth_packet = packet.find(pkt.ethernet)
        ip_packet = packet.find(pkt.ipv4)
        arp_packet = packet.find(pkt.arp)
        icmp_packet = packet.find(pkt.icmp)
        tcp_packet = packet.find(pkt.tcp)
        udp_packet = packet.find(pkt.udp)

        if icmp_packet is None and tcp_packet is None and udp_packet is None and arp_packet is None:
            return

        def flood():
            #Flood incoming packet if dst is not known yet
            #Do not update flow table
            if (arp_packet is None):
                print "Flooding packet in switch: " + dpidToStr(event.connection.dpid) + " --- dst=" + str(eth_packet.dst) + '\n'
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)


        dstEntry = core.host_tracker.getMacEntry(eth_packet.dst)
        if dstEntry is None or arp_packet is not None:
            return flood()

        print "Calculating packet path in switch: " + dpidToStr(event.connection.dpid) + " --- dst=" + str(eth_packet.dst)

        dst = dstEntry.dpid

        if (dst == dpid):
            port = dstEntry.port
        else:

            paths = [[neighbour] for neighbour in self.getNeighbours(dpid)]
            dsts = self.getPathsToDst(paths, dst)
            while not dsts:
                oldPaths = paths
                paths = []
                for path in oldPaths:
                    neighbours = self.getNeighbours(path[-1].dpid2)
                    for neighbour in neighbours:
                        paths.append(path + [neighbour])
                dsts = self.getPathsToDst(paths, dst)
            
            #dsts has all possible minnimum paths to dst
            dstPath = dsts[self.getHash(ip_packet, tcp_packet, udp_packet) % len(dsts)]
            port = dstPath[0].port1



        text = "Making rule for sending packet in switch: " + dpidToStr(event.connection.dpid) + '\n'
        text += "Ethernet: " + str(eth_packet.src) + " -> " + str(eth_packet.dst) + '\n'

        #update flow table
        msg = of.ofp_flow_mod()
        msg.match.dl_type = eth_packet.type
        msg.match.nw_src = ip_packet.srcip
        msg.match.nw_dst = ip_packet.dstip
        msg.match.nw_proto = ip_packet.protocol
        text += "IPv4: " + str(ip_packet.srcip) + " -> " + str(ip_packet.dstip) + '\n'
        if tcp_packet is not None:
            msg.match.tp_src = tcp_packet.srcport
            msg.match.tp_dst = tcp_packet.dstport
            text += "TCP: " + str(tcp_packet.srcport) + " -> " + str(tcp_packet.dstport) + '\n'
        if udp_packet is not None:
            msg.match.tp_src = udp_packet.srcport
            msg.match.tp_dst = udp_packet.dstport
            text += "UDP: " + str(udp_packet.srcport) + " -> " + str(udp_packet.dstport) + '\n'
        msg.actions.append(of.ofp_action_output(port = port))
        event.connection.send(msg)
        print text

        #send packet
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)



    def getNeighbours(self, dpid):
        neighbours = []
        for adjacency in core.openflow_discovery.adjacency:
            if adjacency.dpid1 == dpid:
                neighbours.append(adjacency)
        return neighbours

    def getPathsToDst(self, paths, dst):
        dstPaths = []
        for path in paths:
            if path[-1].dpid2 == dst:
                dstPaths.append(path)
        return dstPaths

    def getHash(self, ip_packet, tcp_packet, udp_packet):
        number = abs(hash((ip_packet.srcip, ip_packet.dstip, ip_packet.protocol)))

        if tcp_packet is not None:
            number += abs(hash((tcp_packet.srcport, tcp_packet.dstport)))
        if udp_packet is not None:
            number += abs(hash((udp_packet.srcport, udp_packet.dstport)))

        return number


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