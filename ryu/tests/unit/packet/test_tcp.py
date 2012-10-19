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
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet import packet_utils


LOG = logging.getLogger('test_tcp')


class Test_tcp(unittest.TestCase):
    """ Test case for tcp
    """
    src_port = 6431
    dst_port = 8080
    seq = 5
    ack = 1
    offset = 6
    bits = 0b101010
    window_size = 2048
    csum = 12345
    urgent = 128
    option = '\x01\x02\x03\x04'

    t = tcp(src_port, dst_port, seq, ack, offset, bits,
            window_size, csum, urgent, option)

    buf = pack(tcp._PACK_STR, src_port, dst_port, seq, ack,
               offset << 4, bits, window_size, csum, urgent)
    buf += option

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.src_port, self.t.src_port)
        eq_(self.dst_port, self.t.dst_port)
        eq_(self.seq, self.t.seq)
        eq_(self.ack, self.t.ack)
        eq_(self.offset, self.t.offset)
        eq_(self.bits, self.t.bits)
        eq_(self.window_size, self.t.window_size)
        eq_(self.csum, self.t.csum)
        eq_(self.urgent, self.t.urgent)
        eq_(self.option, self.t.option)

    def test_parser(self):
        r1, r2 = self.t.parser(self.buf)

        eq_(self.src_port, r1.src_port)
        eq_(self.dst_port, r1.dst_port)
        eq_(self.seq, r1.seq)
        eq_(self.ack, r1.ack)
        eq_(self.offset, r1.offset)
        eq_(self.bits, r1.bits)
        eq_(self.window_size, r1.window_size)
        eq_(self.csum, r1.csum)
        eq_(self.urgent, r1.urgent)
        eq_(self.option, r1.option)
        eq_(None, r2)

    def test_serialize(self):
        offset = 5
        csum = 0

        src_ip = int(netaddr.IPAddress('192.168.10.1'))
        dst_ip = int(netaddr.IPAddress('192.168.100.1'))
        prev = ipv4(4, 5, 0, 0, 0, 0, 0, 64,
                    inet.IPPROTO_UDP, 0, src_ip, dst_ip)

        t = tcp(self.src_port, self.dst_port, self.seq, self.ack,
                offset, self.bits, self.window_size, csum, self.urgent)
        buf = t.serialize(bytearray(), prev)
        res = struct.unpack(tcp._PACK_STR, str(buf))

        eq_(res[0], self.src_port)
        eq_(res[1], self.dst_port)
        eq_(res[2], self.seq)
        eq_(res[3], self.ack)
        eq_(res[4], offset << 4)
        eq_(res[5], self.bits)
        eq_(res[6], self.window_size)
        eq_(res[8], self.urgent)

        # checksum
        ph = struct.pack('!IIBBH', src_ip, dst_ip, 0, 6, offset * 4)
        d = ph + buf + bytearray()
        s = packet_utils.checksum(d)
        eq_(0, s)

    def test_serialize_option(self):
        offset = 6
        csum = 0
        option = '\x01\x02'

        src_ip = int(netaddr.IPAddress('192.168.10.1'))
        dst_ip = int(netaddr.IPAddress('192.168.100.1'))
        prev = ipv4(4, 5, 0, 0, 0, 0, 0, 64,
                    inet.IPPROTO_UDP, 0, src_ip, dst_ip)

        t = tcp(self.src_port, self.dst_port, self.seq, self.ack,
                offset, self.bits, self.window_size, csum, self.urgent,
                option)
        buf = t.serialize(bytearray(), prev)
        r_option = buf[tcp._MIN_LEN:tcp._MIN_LEN + len(option)]
        eq_(option, r_option)

    @raises(Exception)
    def test_malformed_tcp(self):
        m_short_buf = self.buf[1:tcp._MIN_LEN]
        tcp.parser(m_short_buf)
