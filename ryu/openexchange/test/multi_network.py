#!/usr/bin/python

"""
    This example create 7 sub-networks to connect 7  domain controllers.
    Each domain network contains at least 5 switches.
    For an easy test, we add 2 hosts per switch.

    So, in our topology, we have at least 35 switches and 70 hosts.
    Hope it will work perfectly.

"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
import logging
import os

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel


def multiControllerNet(con_num=7, sw_num=35, host_num=70):
    "Create a network from semi-scratch with multiple controllers."
    controller_list = []
    switch_list = []
    host_list = []

    logger = logging.getLogger('ryu.openexchange.test.multi_network')

    net = Mininet(controller=None,
                  switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    for i in xrange(con_num):
        name = 'controller[%s]' % str(i)
        c = net.addController(name, controller=RemoteController,
                              port=6661 + i)
        controller_list.append(c)
        logger.info("*** Creating %s" % name)

    logger.info("*** Creating switches")
    switch_list = [net.addSwitch('s%d' % n) for n in xrange(int(sw_num))]

    logger.info("*** Creating hosts")
    host_list = [net.addHost('h%d' % n) for n in xrange(host_num)]

    logger.info("*** Creating links of host2switch.")
    for i in xrange(0, sw_num):
        net.addLink(switch_list[i], host_list[i*2])
        net.addLink(switch_list[i], host_list[i*2+1])

    logger.info("*** Creating interior links of switch2switch.")
    for i in xrange(0, sw_num, sw_num/con_num):
        for j in xrange(sw_num/con_num):
            for k in xrange(sw_num/con_num):
                if j != k and j > k:
                    net.addLink(switch_list[i+j], switch_list[i+k])

    logger.info("*** Creating intra links of switch2switch.")

    # 0-4  5-9 10-14 15-19 20-24 25-29 30-34
    # domain1 -> others
    net.addLink(switch_list[4], switch_list[6])
    net.addLink(switch_list[4], switch_list[10])
    net.addLink(switch_list[1], switch_list[15])
    net.addLink(switch_list[1], switch_list[20])

    # domain2 -> others
    net.addLink(switch_list[6], switch_list[10])
    net.addLink(switch_list[8], switch_list[12])
    # net.addLink(switch_list[8], switch_list[18])
    net.addLink(switch_list[7], switch_list[25])

    # domain3 -> others
    net.addLink(switch_list[10], switch_list[16])
    net.addLink(switch_list[12], switch_list[16])
    # net.addLink(switch_list[10], switch_list[21])
    net.addLink(switch_list[12], switch_list[27])

    # domain4 -> others
    net.addLink(switch_list[16], switch_list[21])
    net.addLink(switch_list[18], switch_list[27])
    # net.addLink(switch_list[18], switch_list[31])
    net.addLink(switch_list[19], switch_list[34])

    # domain5 -> others
    net.addLink(switch_list[21], switch_list[27])
    net.addLink(switch_list[23], switch_list[31])

    # domain6 -> others
    net.addLink(switch_list[25], switch_list[31])
    net.addLink(switch_list[27], switch_list[32])

    #domain7 has not need to add links.

    logger.info("*** Starting network")
    net.build()
    for c in controller_list:
        c.start()

    _No = 0
    for i in xrange(0, sw_num, sw_num/con_num):
        for j in xrange(sw_num/con_num):
            switch_list[i+j].start([controller_list[_No]])
        _No += 1

    logger.debug("*** Setting OpenFlow version")
    for sw in switch_list:
        cmd = "sudo ovs-vsctl set bridge %s protocols=OpenFlow13" % sw
        os.system(cmd)

    logger.info("*** Running CLI")
    CLI(net)

    logger.info("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')  # for CLI output
    multiControllerNet(con_num=7, sw_num=35, host_num=70)
