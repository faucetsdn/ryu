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
from struct import *
from nose.tools import *
from ryu.ofproto import ether
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.arp import arp
from ryu.lib.packet.vlan import vlan
from ryu.lib import addrconv


LOG = logging.getLogger('test_arp')


class Test_arp(unittest.TestCase):
    """ Test case for arp
    """

    hwtype = 1
    proto = 0x0800
    hlen = 6
    plen = 4
    opcode = 1
    src_mac = '00:07:0d:af:f4:54'
    src_ip = '24.166.172.1'
    dst_mac = '00:00:00:00:00:00'
    dst_ip = '24.166.173.159'

    fmt = arp._PACK_STR
    buf = pack(fmt, hwtype, proto, hlen, plen, opcode,
               addrconv.mac.text_to_bin(src_mac),
               addrconv.ipv4.text_to_bin(src_ip),
               addrconv.mac.text_to_bin(dst_mac),
               addrconv.ipv4.text_to_bin(dst_ip))

    a = arp(hwtype, proto, hlen, plen, opcode, src_mac, src_ip, dst_mac,
            dst_ip)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        eq_(self.hwtype, self.a.hwtype)
        eq_(self.proto, self.a.proto)
        eq_(self.hlen, self.a.hlen)
        eq_(self.plen, self.a.plen)
        eq_(self.opcode, self.a.opcode)
        eq_(self.src_mac, self.a.src_mac)
        eq_(self.src_ip, self.a.src_ip)
        eq_(self.dst_mac, self.a.dst_mac)
        eq_(self.dst_ip, self.a.dst_ip)

    def test_parser(self):
        _res = self.a.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        eq_(res.hwtype, self.hwtype)
        eq_(res.proto, self.proto)
        eq_(res.hlen, self.hlen)
        eq_(res.plen, self.plen)
        eq_(res.opcode, self.opcode)
        eq_(res.src_mac, self.src_mac)
        eq_(res.src_ip, self.src_ip)
        eq_(res.dst_mac, self.dst_mac)
        eq_(res.dst_ip, self.dst_ip)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.a.serialize(data, prev)

        fmt = arp._PACK_STR
        res = struct.unpack(fmt, buf)

        eq_(res[0], self.hwtype)
        eq_(res[1], self.proto)
        eq_(res[2], self.hlen)
        eq_(res[3], self.plen)
        eq_(res[4], self.opcode)
        eq_(res[5], addrconv.mac.text_to_bin(self.src_mac))
        eq_(res[6], addrconv.ipv4.text_to_bin(self.src_ip))
        eq_(res[7], addrconv.mac.text_to_bin(self.dst_mac))
        eq_(res[8], addrconv.ipv4.text_to_bin(self.dst_ip))

    def _build_arp(self, vlan_enabled):
        if vlan_enabled is True:
            ethertype = ether.ETH_TYPE_8021Q
            v = vlan(1, 1, 3, ether.ETH_TYPE_ARP)
        else:
            ethertype = ether.ETH_TYPE_ARP
        e = ethernet(self.dst_mac, self.src_mac, ethertype)
        p = Packet()

        p.add_protocol(e)
        if vlan_enabled is True:
            p.add_protocol(v)
        p.add_protocol(self.a)
        p.serialize()
        return p

    def test_build_arp_vlan(self):
        p = self._build_arp(True)

        e = self.find_protocol(p, "ethernet")
        ok_(e)
        eq_(e.ethertype, ether.ETH_TYPE_8021Q)

        v = self.find_protocol(p, "vlan")
        ok_(v)
        eq_(v.ethertype, ether.ETH_TYPE_ARP)

        a = self.find_protocol(p, "arp")
        ok_(a)

        eq_(a.hwtype, self.hwtype)
        eq_(a.proto, self.proto)
        eq_(a.hlen, self.hlen)
        eq_(a.plen, self.plen)
        eq_(a.opcode, self.opcode)
        eq_(a.src_mac, self.src_mac)
        eq_(a.src_ip, self.src_ip)
        eq_(a.dst_mac, self.dst_mac)
        eq_(a.dst_ip, self.dst_ip)

    def test_build_arp_novlan(self):
        p = self._build_arp(False)

        e = self.find_protocol(p, "ethernet")
        ok_(e)
        eq_(e.ethertype, ether.ETH_TYPE_ARP)

        a = self.find_protocol(p, "arp")
        ok_(a)

        eq_(a.hwtype, self.hwtype)
        eq_(a.proto, self.proto)
        eq_(a.hlen, self.hlen)
        eq_(a.plen, self.plen)
        eq_(a.opcode, self.opcode)
        eq_(a.src_mac, self.src_mac)
        eq_(a.src_ip, self.src_ip)
        eq_(a.dst_mac, self.dst_mac)
        eq_(a.dst_ip, self.dst_ip)

    @raises(Exception)
    def test_malformed_arp(self):
        m_short_buf = self.buf[1:arp._MIN_LEN]
        arp.parser(m_short_buf)

    def test_json(self):
        jsondict = self.a.to_jsondict()
        a = arp.from_jsondict(jsondict['arp'])
        eq_(str(self.a), str(a))
