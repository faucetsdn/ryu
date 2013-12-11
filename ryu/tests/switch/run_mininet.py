#!/usr/bin/env python

from mininet.cli import CLI
from mininet.link import Link
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm

if '__main__' == __name__:
    net = Mininet(controller=RemoteController)

    c0 = net.addController('c0')

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    Link(s1, s2)
    Link(s1, s2)

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    s1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    s2.cmd('ovs-vsctl set Bridge s2 protocols=OpenFlow13')

    CLI(net)

    net.stop()
