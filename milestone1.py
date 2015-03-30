#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

def mutate_net(net):
    AA_h1 = net.addHost('AA_h1')
    AA_h2 = net.addHost('AA_h2')
    AB_h1 = net.addHost('AB_h1')
    AB_h2 = net.addHost('AB_h2')
    BA_h1 = net.addHost('BA_h1')
    BA_h2 = net.addHost('BA_h2')
    BB_h1 = net.addHost('BB_h1')
    BB_h2 = net.addHost('BB_h2')       

    # what ip address?
    ca = net.addController(RemoteController('ca',ip="127.0.0.1"))
    cb = net.addController(RemoteController('cb',ip="127.0.0.1"))

    # OVS Kernel Switches
    A = net.addSwitch('A',OVSSwitch())
    AA = net.addSwitch("AA",OVSSwitch())
    AB = net.addSwitch("AB",OVSSwitch())

    B = net.addSwitch('B')
    BA = net.addSwitch("BA")
    BB = net.addSwitch("BB")
            
    # Bottom level links
    net.addLink(AA,AA_h1)
    net.addLink(AA,AA_h2)
    net.addLink(AB,AB_h1)
    net.addLink(AB,AB_h2)
    net.addLink(BA,BA_h1)
    net.addLink(BA,BA_h1)
    net.addLink(BB,BB_h1)
    net.addLink(BB,BB_h1)

    net.addLink(A,AA)
    net.addLink(A,AB)
    net.addLink(B,BA)
    net.addLink(B,BB)

    net.addLink(ca,A)
    net.addLink(cb,B)
        
    return net

def run():
    net = mutate_net(Mininet())
    
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    net.stop()

        
if __name__ == "__main__":
    run()
