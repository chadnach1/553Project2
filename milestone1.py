#!/usr/bin/env python

from mininet.net import Mininet
#from mininet.node import Controller
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

    ca = net.addController('ca')
    cb = net.addController('cb')

    A = net.addSwitch('A')
    AA = net.addSwitch("AA")
    AB = net.addSwitch("AB")

    B = net.addSwitch('B')
    BA = net.addSwitch("BA")
    BB = net.addSwitch("BB")
            
    net.addLink(AA,AA_h1)
    net.addLink(AA,AA_h2
        
    return net

def run():
    net = mutate_net(Mininet(topo))
    
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    net.stop()

        
if __name__ == "__main__":
    run()
