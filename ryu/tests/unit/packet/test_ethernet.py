# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import six
import struct
import netaddr
from struct import *
from nose.tools import *
from ryu.ofproto import ether, inet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.arp import arp
from ryu.lib import addrconv


LOG = logging.getLogger('test_ethernet')


class Test_ethernet(unittest.TestCase):
    """ Test case for ethernet
    """

    dst = 'aa:aa:aa:aa:aa:aa'
    src = 'bb:bb:bb:bb:bb:bb'
    ethertype = ether.ETH_TYPE_ARP

    buf = pack(ethernet._PACK_STR,
               addrconv.mac.text_to_bin(dst),
               addrconv.mac.text_to_bin(src), ethertype)

    e = ethernet(dst, src, ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        eq_(self.dst, self.e.dst)
        eq_(self.src, self.e.src)
        eq_(self.ethertype, self.e.ethertype)

    def test_parser(self):
        res, ptype, _ = self.e.parser(self.buf)
        LOG.debug((res, ptype))

        eq_(res.dst, self.dst)
        eq_(res.src, self.src)
        eq_(res.ethertype, self.ethertype)
        eq_(ptype, arp)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.e.serialize(data, prev)

        fmt = ethernet._PACK_STR
        res = struct.unpack(fmt, buf)

        eq_(res[0], addrconv.mac.text_to_bin(self.dst))
        eq_(res[1], addrconv.mac.text_to_bin(self.src))
        eq_(res[2], self.ethertype)

    @raises(Exception)
    def test_malformed_ethernet(self):
        m_short_buf = self.buf[1:ethernet._MIN_LEN]
        ethernet.parser(m_short_buf)

    def test_default_args(self):
        e = ethernet()
        buf = e.serialize(bytearray(), None)
        res = struct.unpack(e._PACK_STR, six.binary_type(buf))

        eq_(res[0], addrconv.mac.text_to_bin('ff:ff:ff:ff:ff:ff'))
        eq_(res[1], addrconv.mac.text_to_bin('00:00:00:00:00:00'))
        eq_(res[2], ether.ETH_TYPE_IP)

    def test_json(self):
        jsondict = self.e.to_jsondict()
        e = ethernet.from_jsondict(jsondict['ethernet'])
        eq_(str(self.e), str(e))
