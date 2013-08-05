# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import inspect
import logging
import socket
import unittest
from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.lib import ip
from ryu.lib import mac
from ryu.lib.packet import dhcp


LOG = logging.getLogger(__name__)


class Test_dhcp_offer(unittest.TestCase):

    op = dhcp.DHCP_BOOT_REPLY
    chaddr = 'AA:AA:AA:AA:AA:AA'
    htype = 1
    hlen = 6
    hops = 0
    xid = 1
    secs = 0
    flags = 1
    ciaddr = '192.168.10.10'
    yiaddr = '192.168.20.20'
    siaddr = '192.168.30.30'
    giaddr = '192.168.40.40'
    sname = 'abc'
    boot_file = ''

    option_list = [dhcp.option('35', '02'),
                   dhcp.option('01', 'ffffff00'),
                   dhcp.option('03', 'c0a80a09'),
                   dhcp.option('06', 'c0a80a09'),
                   dhcp.option('33', '0003f480'),
                   dhcp.option('3a', '0001fa40'),
                   dhcp.option('3b', '000375f0'),
                   dhcp.option('36', 'c0a80a09')]
    magic_cookie = socket.inet_aton('99.130.83.99')
    options = dhcp.options(option_list=option_list,
                           magic_cookie=magic_cookie)

    dh = dhcp.dhcp(op, chaddr, options, htype=htype, hlen=hlen,
                   hops=hops, xid=xid, secs=secs, flags=flags,
                   ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr,
                   giaddr=giaddr, sname=sname, boot_file=boot_file)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_to_string(self):
        option_values = ['tag', 'length', 'value']
        opt_str_list = []
        for option in self.option_list:
            _opt_str = ','.join(['%s=%s' % (k, repr(getattr(option, k)))
                                 for k, v in inspect.getmembers(option)
                                 if k in option_values])
            opt_str = '%s(%s)' % (dhcp.option.__name__, _opt_str)
            opt_str_list.append(opt_str)
        option_str = '[%s]' % ', '.join(opt_str_list)

        opts_vals = {'magic_cookie': repr(self.magic_cookie),
                     'option_list': option_str,
                     'options_len': repr(self.options.options_len)}
        _options_str = ','.join(['%s=%s' % (k, opts_vals[k])
                                 for k, v in inspect.getmembers(self.options)
                                 if k in opts_vals])
        options_str = '%s(%s)' % (dhcp.options.__name__, _options_str)

        dhcp_values = {'op': repr(self.op),
                       'htype': repr(self.htype),
                       'hlen': repr(self.hlen),
                       'hops': repr(self.hops),
                       'xid': repr(self.xid),
                       'secs': repr(self.secs),
                       'flags': repr(self.flags),
                       'ciaddr': repr(self.ciaddr),
                       'yiaddr': repr(self.yiaddr),
                       'siaddr': repr(self.siaddr),
                       'giaddr': repr(self.giaddr),
                       'chaddr': repr(self.chaddr),
                       'sname': repr(self.sname),
                       'boot_file': repr(self.boot_file),
                       'options': options_str}
        _dh_str = ','.join(['%s=%s' % (k, dhcp_values[k])
                            for k, v in inspect.getmembers(self.dh)
                            if k in dhcp_values])
        dh_str = '%s(%s)' % (dhcp.dhcp.__name__, _dh_str)

        eq_(str(self.dh), dh_str)
        eq_(repr(self.dh), dh_str)
