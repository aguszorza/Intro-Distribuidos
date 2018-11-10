from mininet.topo import Topo
import sys

class MyTopo(Topo):
    def __init__(self, levels=3, hosts=3):
        # Initialize topology
        Topo.__init__(self)
        
        switches = {}

        switch_number = 1
        host_number = 1

        #Add client hosts
        switches[0] = []
        for host in range(hosts):
            name = 'h' + str(host_number)
            switches[0].append(self.addHost(name))
            host_number += 1

        #Add switches
        for level in range(levels):
            switch_count = 2 ** level
            switches[level+1] = []
            for switch in range(switch_count):
                name = 's' + str(switch_number)
                addedSwitch = self.addSwitch(name)
                switches[level+1].append(addedSwitch)
                switch_number += 1
                for link in switches[level]:
                    self.addLink(addedSwitch, link)

        #Add server hosts
        for switch in switches[levels]:
            name = 'h' + str(host_number)
            host = self.addHost(name)
            host_number += 1
            self.addLink(switch, host)





topos = {'topo': (lambda levels=3, hosts=3: MyTopo(levels=levels, hosts=hosts))}
