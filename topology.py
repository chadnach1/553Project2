#!/usr/bin/env python

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections

def start_net(net):
    AA_h1 = net.addHost('AA_h1',mac="00:00:00:00:01:00",ip="10.1.1.1")
    AA_h2 = net.addHost('AA_h2',mac="00:00:00:00:02:00",ip="10.1.1.2")
    AB_h1 = net.addHost('AB_h1',mac="00:00:00:00:03:00",ip="10.1.2.1")
    AB_h2 = net.addHost('AB_h2',mac="00:00:00:00:04:00",ip="10.1.2.2")
    BA_h1 = net.addHost('BA_h1',mac="00:00:00:00:05:00",ip="10.10.10.1")
    BA_h2 = net.addHost('BA_h2',mac="00:00:00:00:06:00",ip="10.10.10.2")
    BB_h1 = net.addHost('BB_h1',mac="00:00:00:00:07:00",ip="10.10.20.1")
    BB_h2 = net.addHost('BB_h2',mac="00:00:00:00:08:00",ip="10.10.20.2") 

    # what ip address?
    ca = net.addController('ca',controller=RemoteController,ip="127.0.0.1",port=6634)
    cb = net.addController('cb',controller=RemoteController,ip="127.0.0.1",port=6635)

    # OVS Kernel Switches
    A = net.addSwitch('A',cls=OVSSwitch,mac="00:00:00:00:00:01",listenport=6634,dpid="1",protocols='OpenFlow13')
    AA = net.addSwitch("AA",cls=OVSSwitch,mac="00:00:00:00:00:02",listenport=6634,dpid="2",protocols='OpenFlow13')
    AB = net.addSwitch("AB",cls=OVSSwitch,mac="00:00:00:00:00:03",listenport=6634,dpid="3",protocols='OpenFlow13')

    B = net.addSwitch('B',cls=OVSSwitch,mac="00:00:00:00:00:04",listenport=6635,dpid="4",protocols='OpenFlow13')
    BA = net.addSwitch("BA",cls=OVSSwitch,mac="00:00:00:00:00:05",listenport=6635,dpid="5",protocols='OpenFlow13')
    BB = net.addSwitch("BB",cls=OVSSwitch,mac="00:00:00:00:00:06",listenport=6635,dpid="6",protocols='OpenFlow13')

    """
    lobot = dict(cls=TCLink,bw=2,delay="2ms",max_queue_size=5)
    lomid = dict(cls=TCLink,bw=5,delay="1ms",max_queue_size=10)
    lotop = dict(cls=TCLink,bw=10,delay="0",max_queue_size=20)
    """
    lobot = dict()
    lomid = dict()
    lotop = dict()

    # Bottom level links
    net.addLink(AA,AA_h1, **lobot)
    net.addLink(AA,AA_h2, **lobot)
    net.addLink(AB,AB_h1, **lobot)
    net.addLink(AB,AB_h2, **lobot)
    net.addLink(BA,BA_h1, **lobot)
    net.addLink(BA,BA_h2, **lobot)
    net.addLink(BB,BB_h1, **lobot)
    net.addLink(BB,BB_h2, **lobot)

    net.addLink(A,AA, **lomid)
    net.addLink(A,AB, **lomid)
    net.addLink(B,BA, **lomid)
    net.addLink(B,BB, **lomid)

    net.addLink(A,B, **lotop)

    net.build()

    A.start([ca])
    AA.start([ca])
    AB.start([ca])
    B.start([cb])
    BA.start([cb])
    BB.start([cb])
        
    return net

def run():
    net = start_net(Mininet(controller=None,autoSetMacs=True))
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    CLI(net)
    net.stop()
        
if __name__ == "__main__":
    run()
