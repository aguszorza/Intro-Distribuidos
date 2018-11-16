
# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.packet as pkt
from pox.lib.revent import *                  # Event library
import pox.lib.recoco as recoco               # Multitasking library
from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer
from pox.host_tracker import host_tracker
import random


# Create a logger for this component
log = core.getLogger()
ports_used = {}
last_port_used = {}

class MyController(EventMixin):

    def __init__ (self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        #Flood multicast packets => arp
        log.info("Flooding multicast packets in switch: " + dpidToStr(event.connection.dpid))
        msg = of.ofp_flow_mod()
        msg.match.dl_dst = EthAddr("ff:ff:ff:ff:ff:ff")
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)

        ports_used[event.dpid] = set()


    def _handle_PacketIn(self, event):
        """ Packet processing """
        packet = event.parsed
        dpid = event.connection.dpid

        eth_packet = packet.find(pkt.ethernet)
        ip_packet = packet.find(pkt.ipv4)
        ip6_packet = packet.find(pkt.ipv6)
        arp_packet = packet.find(pkt.arp)
        icmp_packet = packet.find(pkt.icmp)
        tcp_packet = packet.find(pkt.tcp)
        udp_packet = packet.find(pkt.udp)

        if icmp_packet is None and tcp_packet is None and udp_packet is None and arp_packet is None:
            return
        if ip6_packet is not None:
            return

        def flood():
            #Flood incoming packet if dst is not known yet
            #Do not update flow table
            if (arp_packet is None):
                log.info("Flooding packet in switch: " + dpidToStr(event.connection.dpid) + " --- dst=" + str(eth_packet.dst))
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)


        dstEntry = core.host_tracker.getMacEntry(eth_packet.dst)
        if dstEntry is None or arp_packet is not None:
            return flood()

        log.info("Calculating packet path in switch: " + dpidToStr(event.connection.dpid) + " --- dst=" + str(eth_packet.dst))

        dst = dstEntry.dpid
        port = None

        if (dst == dpid):
            #current switch is destination swith
            port = dstEntry.port
        else:
            #calculate all possible minnimum paths
            paths = [[neighbour] for neighbour in self.getNeighbours(dpid)]
            dsts = self.getPathsToDst(paths, dst)
            while not dsts:
                #for each iteration, calculates all paths from src which has length n
                #if any of those paths end in dst, finish while
                oldPaths = paths
                paths = []
                for path in oldPaths:
                    neighbours = self.getNeighbours(path[-1].dpid2)
                    for neighbour in neighbours:
                        paths.append(path + [neighbour])
                dsts = self.getPathsToDst(paths, dst)
            
            if len(dsts) == 0:
                return
            if len(dsts) == 1:
                port = dsts[0][0].port1

            else:
                #dsts has all possible minimum paths to dst
                for dstPath in dsts:
                    dstPort = dstPath[0].port1
                    if not dstPort in ports_used[dpid]:
                        #Port was not used
                        port = dstPort
                        break

            while not port:
                dstPort = random.choice(dsts)[0].port1
                if dstPort != last_port_used[dpid]:
                    port = dstPort



        text = "Making rule for sending packet in switch: " + dpidToStr(dpid) + '\n'
        text += "Ethernet: " + str(eth_packet.src) + " -> " + str(eth_packet.dst) + '\n'

        #update flow table
        msg = of.ofp_flow_mod()
        msg.match.dl_type = eth_packet.type
        msg.match.nw_src = ip_packet.srcip
        msg.match.nw_dst = ip_packet.dstip
        msg.match.nw_proto = ip_packet.protocol
        text += "IPv4: " + str(ip_packet.srcip) + " -> " + str(ip_packet.dstip)
        if tcp_packet is not None:
            msg.match.tp_src = tcp_packet.srcport
            msg.match.tp_dst = tcp_packet.dstport
            text += "\nTCP: " + str(tcp_packet.srcport) + " -> " + str(tcp_packet.dstport)
        if udp_packet is not None:
            msg.match.tp_src = udp_packet.srcport
            msg.match.tp_dst = udp_packet.dstport
            text += "\nUDP: " + str(udp_packet.srcport) + " -> " + str(udp_packet.dstport)
        msg.actions.append(of.ofp_action_output(port = port))
        event.connection.send(msg)
        print text

        ports_used[dpid].add(port)
        last_port_used[dpid] = port

        #send packet
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)



    def getNeighbours(self, dpid):
        """Returns all neighbours of switch with dpid"""
        neighbours = []
        for adjacency in core.openflow_discovery.adjacency:
            if adjacency.dpid1 == dpid:
                neighbours.append(adjacency)
        return neighbours

    def getPathsToDst(self, paths, dst):
        """Returns all paths from list which end with dst"""
        dstPaths = []
        for path in paths:
            if path[-1].dpid2 == dst:
                dstPaths.append(path)
        return dstPaths



class MyFirewall(EventMixin):

    udp_max_packet = 100
    udp_max_block_time = 5

    def __init__(self):
        core.openflow.addListeners(self)
        core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)
        self.udp_packets = {}
        self.udp_packet_count = {}
        self.blocked = {}
        self.unblockTried = set()

        #Check stats every 5 seconds
        Timer(5, self.requestStats, recurring = True)

    def handle_flow_stats(self, event):
        #Check udp packets sent based in flow table statistics
        dpid = event.dpid
        self.udp_packets[dpid] = {}
        flow_packets = {}
        for flow in event.stats:
            ip = flow.match.nw_dst
            if ip is not None and flow.match.nw_proto == pkt.ipv4.UDP_PROTOCOL:
                #Count packets sent for each udp flow table entry
                flow_packets[ip] = flow_packets.get(ip, 0) + flow.packet_count
        
        for ip in flow_packets.keys():
            #Packets sent in this period is calculated
            #Total udp packets sent - last period udp packets sent
            packets = flow_packets[ip] - self.udp_packet_count.get(dpid, {}).get(ip, 0)
            if packets:
                self.udp_packets[dpid][ip] = packets
                if packets > self.udp_max_packet:
                    self.blockUdp(ip)
                else:
                    self.unblockUdp(ip)
        
        for ip in self.blocked.keys():
            #If ip is blocked and does not have new packets sent, try to unblock
            if not ip in self.udp_packets[dpid].keys():
                self.unblockUdp(ip)

        self.udp_packet_count[dpid] = flow_packets



    def blockUdp(self, ip):
        #Blocks Udp packets in all switches
        blocks = self.blocked.get(ip, 0)
        if not blocks:
            msg = of.ofp_flow_mod()
            msg.match.dl_type = pkt.ethernet.IP_TYPE
            msg.priority = 100
            msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
            msg.match.nw_dst = ip

            for con in core.openflow.connections:
                con.send(msg)

        log.info("Blocking UDP flows for ip dst " + str(ip))
        self.blocked[ip] = self.udp_max_block_time
        self.unblockTried.add(ip)

    def unblockUdp(self, ip):
        if ip in self.unblockTried:
            return

        blocks = self.blocked.get(ip, 0)

        if blocks:
            self.unblockTried.add(ip)
            log.info("Trying to unblock UDP flows for ip dst " + str(ip) + " : " + str(blocks))

            if blocks == 1:
                #It was blocked for self.udp_max_block_time periods
                msg = of.ofp_flow_mod()
                msg.match.dl_type = pkt.ethernet.IP_TYPE
                msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                msg.match.nw_dst = ip
                msg.command = of.OFPFC_DELETE

                log.info("Unblocking UDP flows for ip dst " + str(ip))

                for con in core.openflow.connections:
                    con.send(msg)

            self.blocked[ip] = blocks - 1


    def requestStats(self):
        #Requests udp statistics from the switch that is connected to clients

        self.unblockTried = set()

        for connection in core.openflow.connections:
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))


class MyPortStats(EventMixin):

    def __init__(self):
        #Check port stats every 30 seconds
        Timer(30, self.check_use_of_ports, recurring = True)


    def check_use_of_ports(self):
        for connection in core.openflow.connections:
            switch_ports_used = 0
            switch_ports_total = 0
            dpid = connection.dpid
            for port in connection.ports:
                if port != of.OFPP_LOCAL:
                    switch_ports_total += 1
                    if port in ports_used[dpid]:
                        switch_ports_used += 1
            if switch_ports_total == switch_ports_used:
                text = "All ports used"
            else:
                text = "Ports used: " + str(switch_ports_used) + "/" + str(switch_ports_total)
            log.info("Switch " + dpidToStr(dpid) + ": " + text)



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

    core.registerNew(MyFirewall)
    core.registerNew(MyPortStats)