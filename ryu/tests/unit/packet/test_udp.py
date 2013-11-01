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
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto import ether, inet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.udp import udp
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet import packet_utils
from ryu.lib import addrconv


LOG = logging.getLogger('test_udp')


class Test_udp(unittest.TestCase):
    """ Test case for udp
    """
    src_port = 6431
    dst_port = 8080
    total_length = 65507
    csum = 12345
    u = udp(src_port, dst_port, total_length, csum)
    buf = pack(udp._PACK_STR, src_port, dst_port, total_length, csum)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.src_port, self.u.src_port)
        eq_(self.dst_port, self.u.dst_port)
        eq_(self.total_length, self.u.total_length)
        eq_(self.csum, self.u.csum)

    def test_parser(self):
        r1, r2, _ = self.u.parser(self.buf)

        eq_(self.src_port, r1.src_port)
        eq_(self.dst_port, r1.dst_port)
        eq_(self.total_length, r1.total_length)
        eq_(self.csum, r1.csum)
        eq_(None, r2)

    def test_serialize(self):
        src_port = 6431
        dst_port = 8080
        total_length = 0
        csum = 0

        src_ip = '192.168.10.1'
        dst_ip = '192.168.100.1'
        prev = ipv4(4, 5, 0, 0, 0, 0, 0, 64,
                    inet.IPPROTO_UDP, 0, src_ip, dst_ip)

        u = udp(src_port, dst_port, total_length, csum)
        buf = u.serialize(bytearray(), prev)
        res = struct.unpack(udp._PACK_STR, buf)

        eq_(res[0], src_port)
        eq_(res[1], dst_port)
        eq_(res[2], struct.calcsize(udp._PACK_STR))

        # checksum
        ph = struct.pack('!4s4sBBH',
                         addrconv.ipv4.text_to_bin(src_ip),
                         addrconv.ipv4.text_to_bin(dst_ip), 0, 17, res[2])
        d = ph + buf + bytearray()
        s = packet_utils.checksum(d)
        eq_(0, s)

    @raises(Exception)
    def test_malformed_udp(self):
        m_short_buf = self.buf[1:udp._MIN_LEN]
        udp.parser(m_short_buf)

    def test_default_args(self):
        prev = ipv4(proto=inet.IPPROTO_UDP)
        u = udp()
        buf = u.serialize(bytearray(), prev)
        res = struct.unpack(udp._PACK_STR, buf)

        eq_(res[0], 0)
        eq_(res[1], 0)
        eq_(res[2], udp._MIN_LEN)
