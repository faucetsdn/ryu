# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
import inspect
import logging

from struct import pack, unpack_from
from nose.tools import ok_, eq_, raises
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.packet_utils import checksum
from ryu.lib import addrconv
from ryu.lib.packet.igmp import igmp
from ryu.lib.packet.igmp import IGMP_TYPE_QUERY

LOG = logging.getLogger(__name__)


class Test_igmp(unittest.TestCase):
    """ Test case for Internet Group Management Protocol
    """
    def setUp(self):
        self.msgtype = IGMP_TYPE_QUERY
        self.maxresp = 100
        self.csum = 0
        self.address = '225.0.0.1'

        self.buf = pack(igmp._PACK_STR, self.msgtype, self.maxresp,
                        self.csum,
                        addrconv.ipv4.text_to_bin(self.address))

        self.g = igmp(self.msgtype, self.maxresp, self.csum,
                      self.address)

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        eq_(self.msgtype, self.g.msgtype)
        eq_(self.maxresp, self.g.maxresp)
        eq_(self.csum, self.g.csum)
        eq_(self.address, self.g.address)

    def test_parser(self):
        _res = self.g.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        eq_(res.msgtype, self.msgtype)
        eq_(res.maxresp, self.maxresp)
        eq_(res.csum, self.csum)
        eq_(res.address, self.address)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.g.serialize(data, prev)

        res = unpack_from(igmp._PACK_STR, buffer(buf))

        eq_(res[0], self.msgtype)
        eq_(res[1], self.maxresp)
        eq_(res[2], checksum(self.buf))
        eq_(res[3], addrconv.ipv4.text_to_bin(self.address))

    def _build_igmp(self):
        dl_dst = '11:22:33:44:55:66'
        dl_src = 'aa:bb:cc:dd:ee:ff'
        dl_type = ether.ETH_TYPE_IP
        e = ethernet(dl_dst, dl_src, dl_type)

        total_length = 20 + igmp._MIN_LEN
        nw_proto = inet.IPPROTO_IGMP
        nw_dst = '11.22.33.44'
        nw_src = '55.66.77.88'
        i = ipv4(total_length=total_length, src=nw_src, dst=nw_dst,
                 proto=nw_proto)

        p = Packet()

        p.add_protocol(e)
        p.add_protocol(i)
        p.add_protocol(self.g)
        p.serialize()
        return p

    def test_build_igmp(self):
        p = self._build_igmp()

        e = self.find_protocol(p, "ethernet")
        ok_(e)
        eq_(e.ethertype, ether.ETH_TYPE_IP)

        i = self.find_protocol(p, "ipv4")
        ok_(i)
        eq_(i.proto, inet.IPPROTO_IGMP)

        g = self.find_protocol(p, "igmp")
        ok_(g)

        eq_(g.msgtype, self.msgtype)
        eq_(g.maxresp, self.maxresp)
        eq_(g.csum, checksum(self.buf))
        eq_(g.address, self.address)

    def test_to_string(self):
        igmp_values = {'msgtype': repr(self.msgtype),
                       'maxresp': repr(self.maxresp),
                       'csum': repr(self.csum),
                       'address': repr(self.address)}
        _g_str = ','.join(['%s=%s' % (k, igmp_values[k])
                           for k, v in inspect.getmembers(self.g)
                           if k in igmp_values])
        g_str = '%s(%s)' % (igmp.__name__, _g_str)

        eq_(str(self.g), g_str)
        eq_(repr(self.g), g_str)

    @raises(Exception)
    def test_malformed_igmp(self):
        m_short_buf = self.buf[1:igmp._MIN_LEN]
        igmp.parser(m_short_buf)
