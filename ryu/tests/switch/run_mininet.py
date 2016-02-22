#!/usr/bin/env python

import sys

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.node import UserSwitch

from oslo_config import cfg
from ryu import version
from ryu.ofproto.ofproto_common import OFP_TCP_PORT


if '__main__' == __name__:

    opts = [
        cfg.StrOpt('switch', default='ovs',
                   help='test switch [ovs|cpqd]'),
        cfg.StrOpt('protocols', default='OpenFlow13',
                   help='"protocols" option for ovs-vsctl (e.g. OpenFlow13)')
    ]
    conf = cfg.ConfigOpts()
    conf.register_cli_opts(opts)
    conf(project='ryu', version='run_mininet.py %s' % version)
    conf(sys.argv[1:])
    switch_type = {'ovs': OVSSwitch, 'cpqd': UserSwitch}
    switch = switch_type.get(conf.switch, None)
    if switch is None:
        raise ValueError('Invalid switch type. [%s]', conf.switch)

    net = Mininet(switch=switch, controller=RemoteController)

    c0 = net.addController('c0', port=OFP_TCP_PORT)

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    net.addLink(s1, s2)
    net.addLink(s1, s2)
    net.addLink(s1, s2)

    net.start()

    if conf.switch == 'ovs':
        s1.cmd('ovs-vsctl set Bridge s1 protocols=%s' % conf.protocols)
        s2.cmd('ovs-vsctl set Bridge s2 protocols=%s' % conf.protocols)

    CLI(net)

    net.stop()
