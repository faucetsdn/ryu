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
from struct import *
from nose.tools import *
from ryu.ofproto import ether, inet
from ryu.lib.packet import packet_utils
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.tcp import tcp
from ryu.lib import addrconv


LOG = logging.getLogger('test_ipv4')


class Test_ipv4(unittest.TestCase):
    """ Test case for ipv4
    """

    version = 4
    header_length = 5 + 10
    ver_hlen = version << 4 | header_length
    tos = 0
    total_length = header_length + 64
    identification = 30774
    flags = 4
    offset = 1480
    flg_off = flags << 13 | offset
    ttl = 64
    proto = inet.IPPROTO_TCP
    csum = 0xadc6
    src = '131.151.32.21'
    dst = '131.151.32.129'
    length = header_length * 4
    option = b'\x86\x28\x00\x00\x00\x01\x01\x22' \
        + b'\x00\x01\xae\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x01'

    buf = pack(ipv4._PACK_STR, ver_hlen, tos, total_length, identification,
               flg_off, ttl, proto, csum,
               addrconv.ipv4.text_to_bin(src),
               addrconv.ipv4.text_to_bin(dst)) \
        + option

    ip = ipv4(version, header_length, tos, total_length, identification,
              flags, offset, ttl, proto, csum, src, dst, option)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.version, self.ip.version)
        eq_(self.header_length, self.ip.header_length)
        eq_(self.tos, self.ip.tos)
        eq_(self.total_length, self.ip.total_length)
        eq_(self.identification, self.ip.identification)
        eq_(self.flags, self.ip.flags)
        eq_(self.offset, self.ip.offset)
        eq_(self.ttl, self.ip.ttl)
        eq_(self.proto, self.ip.proto)
        eq_(self.csum, self.ip.csum)
        eq_(self.src, self.ip.src)
        eq_(self.dst, self.ip.dst)
        eq_(self.length, len(self.ip))
        eq_(self.option, self.ip.option)

    def test_parser(self):
        res, ptype, _ = self.ip.parser(self.buf)

        eq_(res.version, self.version)
        eq_(res.header_length, self.header_length)
        eq_(res.tos, self.tos)
        eq_(res.total_length, self.total_length)
        eq_(res.identification, self.identification)
        eq_(res.flags, self.flags)
        eq_(res.offset, self.offset)
        eq_(res.ttl, self.ttl)
        eq_(res.proto, self.proto)
        eq_(res.csum, self.csum)
        eq_(res.src, self.src)
        eq_(res.dst, self.dst)
        eq_(ptype, tcp)

    def test_serialize(self):
        buf = self.ip.serialize(bytearray(), None)
        res = struct.unpack_from(ipv4._PACK_STR, six.binary_type(buf))
        option = buf[ipv4._MIN_LEN:ipv4._MIN_LEN + len(self.option)]

        eq_(res[0], self.ver_hlen)
        eq_(res[1], self.tos)
        eq_(res[2], self.total_length)
        eq_(res[3], self.identification)
        eq_(res[4], self.flg_off)
        eq_(res[5], self.ttl)
        eq_(res[6], self.proto)
        eq_(res[8], addrconv.ipv4.text_to_bin(self.src))
        eq_(res[9], addrconv.ipv4.text_to_bin(self.dst))
        eq_(option, self.option)

        # checksum
        csum = packet_utils.checksum(buf)
        eq_(csum, 0)

    @raises(Exception)
    def test_malformed_ipv4(self):
        m_short_buf = self.buf[1:ipv4._MIN_LEN]
        ipv4.parser(m_short_buf)

    def test_json(self):
        jsondict = self.ip.to_jsondict()
        ip = ipv4.from_jsondict(jsondict['ipv4'])
        eq_(str(self.ip), str(ip))
