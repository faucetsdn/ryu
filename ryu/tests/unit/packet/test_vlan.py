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
import struct
import netaddr
from struct import *
from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto import ether, inet
from ryu.lib import mac
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.vlan import vlan


LOG = logging.getLogger('test_vlan')


class Test_vlan(unittest.TestCase):
    """ Test case for vlan
    """

    pcp = 0
    cfi = 0
    vid = 32
    tci = pcp << 15 | cfi << 12 | vid
    ethertype = ether.ETH_TYPE_IP
    length = struct.calcsize(vlan._PACK_STR)

    buf = pack(vlan._PACK_STR, tci, ethertype)

    v = vlan(pcp, cfi, vid, ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        eq_(self.pcp, self.v.pcp)
        eq_(self.cfi, self.v.cfi)
        eq_(self.vid, self.v.vid)
        eq_(self.ethertype, self.v.ethertype)
        eq_(self.length, self.v.length)

    def test_parser(self):
        res, ptype = self.v.parser(self.buf)

        eq_(res.pcp, self.pcp)
        eq_(res.cfi, self.cfi)
        eq_(res.vid, self.vid)
        eq_(res.ethertype, self.ethertype)
        eq_(res.length, self.length)
        eq_(ptype, ipv4)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.v.serialize(data, prev)

        fmt = vlan._PACK_STR
        res = struct.unpack(fmt, buf)

        eq_(res[0], self.tci)
        eq_(res[1], self.ethertype)

    def _build_vlan(self):
        src_mac = mac.haddr_to_bin('00:07:0d:af:f4:54')
        dst_mac = mac.haddr_to_bin('00:00:00:00:00:00')
        ethertype = ether.ETH_TYPE_8021Q
        e = ethernet(dst_mac, src_mac, ethertype)

        version = 4
        header_length = 20
        tos = 0
        total_length = 24
        identification = 0x8a5d
        flags = 0
        offset = 1480
        ttl = 64
        proto = inet.IPPROTO_ICMP
        csum = 0xa7f2
        src = int(netaddr.IPAddress('131.151.32.21'))
        dst = int(netaddr.IPAddress('131.151.32.129'))
        option = 'TEST'
        ip = ipv4(version, header_length, tos, total_length, identification,
                  flags, offset, ttl, proto, csum, src, dst, option)

        p = Packet()

        p.add_protocol(e)
        p.add_protocol(self.v)
        p.add_protocol(ip)
        p.serialize()

        return p

    def test_build_vlan(self):
        p = self._build_vlan()

        e = self.find_protocol(p, "ethernet")
        ok_(e)
        eq_(e.ethertype, ether.ETH_TYPE_8021Q)

        v = self.find_protocol(p, "vlan")
        ok_(v)
        eq_(v.ethertype, ether.ETH_TYPE_IP)

        ip = self.find_protocol(p, "ipv4")
        ok_(ip)

        eq_(v.pcp, self.pcp)
        eq_(v.cfi, self.cfi)
        eq_(v.vid, self.vid)
        eq_(v.ethertype, self.ethertype)
        eq_(v.length, self.length)

    @raises(Exception)
    def test_malformed_vlan(self):
        m_short_buf = self.buf[1:vlan._MIN_LEN]
        vlan.parser(m_short_buf)
