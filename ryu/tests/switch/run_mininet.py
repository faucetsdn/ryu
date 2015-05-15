#!/usr/bin/env python

import sys

from mininet.cli import CLI
from mininet.link import Link
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.node import UserSwitch
from mininet.term import makeTerm

from oslo_config import cfg
from ryu import version

if '__main__' == __name__:

    opts = [
        cfg.StrOpt('switch', default='ovs',
                   help='test switch (ovs|ovs13|ovs14|cpqd)')
    ]
    conf = cfg.ConfigOpts()
    conf.register_cli_opts(opts)
    conf(project='ryu', version='run_mininet.py %s' % version)
    conf(sys.argv[1:])
    switch_type = {'ovs': OVSSwitch, 'ovs13': OVSSwitch,
                   'ovs14': OVSSwitch, 'cpqd': UserSwitch}
    switch = switch_type.get(conf.switch)
    if switch is None:
        raise ValueError('Invalid switch type. [%s]', conf.switch)

    net = Mininet(switch=switch, controller=RemoteController)

    c0 = net.addController('c0')

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    Link(s1, s2)
    Link(s1, s2)
    Link(s1, s2)

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    if conf.switch in ['ovs', 'ovs13']:
        s1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
        s2.cmd('ovs-vsctl set Bridge s2 protocols=OpenFlow13')
    elif conf.switch == 'ovs14':
        s1.cmd('ovs-vsctl set Bridge s1 protocols=OpenFlow14')
        s2.cmd('ovs-vsctl set Bridge s2 protocols=OpenFlow14')

    CLI(net)

    net.stop()
