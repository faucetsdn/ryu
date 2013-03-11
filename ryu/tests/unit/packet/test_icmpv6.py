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
import socket

from nose.tools import ok_, eq_, nottest, raises
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto import ether, inet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import icmpv6
from ryu.lib.packet.ipv6 import ipv6
from ryu.lib.packet import packet_utils


LOG = logging.getLogger(__name__)


def icmpv6_csum(prev, buf):
    ph = struct.pack('!16s16sBBH', prev.src, prev.dst, 0, prev.nxt,
                     prev.payload_length)
    h = bytearray(buf)
    struct.pack_into('!H', h, 2, 0)

    return socket.htons(packet_utils.checksum(ph + h))


class Test_icmpv6_header(unittest.TestCase):
    type_ = 255
    code = 0
    csum = 207
    buf = '\xff\x00\x00\xcf'
    icmp = icmpv6.icmpv6(type_, code, 0)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_, self.icmp.type_)
        eq_(self.code, self.icmp.code)
        eq_(0, self.icmp.csum)

    def test_parser(self):
        msg, n = self.icmp.parser(self.buf)

        eq_(msg.type_, self.type_)
        eq_(msg.code, self.code)
        eq_(msg.csum, self.csum)
        eq_(msg.data, None)
        eq_(n, None)

    def test_serialize(self):
        src_ipv6 = netaddr.IPAddress('fe80::200:ff:fe00:ef').packed
        dst_ipv6 = netaddr.IPAddress('fe80::200:ff:fe00:1').packed
        prev = ipv6(6, 0, 0, 4, 58, 255, src_ipv6, dst_ipv6)

        buf = self.icmp.serialize(bytearray(), prev)
        (type_, code, csum) = struct.unpack(self.icmp._PACK_STR, buffer(buf))

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, self.csum)

    @raises(Exception)
    def test_malformed_icmpv6(self):
        m_short_buf = self.buf[1:self.icmp._MIN_LEN]
        self.icmp.parser(m_short_buf)


class Test_icmpv6_echo_request(unittest.TestCase):
    type_ = 128
    code = 0
    csum = 0xa572
    id_ = 0x7620
    seq = 0
    data = '\x01\xc9\xe7\x36\xd3\x39\x06\x00'
    buf = '\x80\x00\xa5\x72\x76\x20\x00\x00'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        echo = icmpv6.echo(0, 0)
        eq_(echo.id, 0)
        eq_(echo.seq, 0)
        eq_(echo.data, None)

    def _test_parser(self, data=None):
        buf = self.buf + str(data or '')
        msg, n = icmpv6.icmpv6.parser(buf)

        eq_(msg.type_, self.type_)
        eq_(msg.code, self.code)
        eq_(msg.csum, self.csum)
        eq_(msg.data.id, self.id_)
        eq_(msg.data.seq, self.seq)
        eq_(msg.data.data, data)
        eq_(n, None)

    def test_parser_without_data(self):
        self._test_parser()

    def test_parser_with_data(self):
        self._test_parser(self.data)

    def _test_serialize(self, echo_data=None):
        buf = self.buf + str(echo_data or '')
        src_ipv6 = netaddr.IPAddress('3ffe:507:0:1:200:86ff:fe05:80da').packed
        dst_ipv6 = netaddr.IPAddress('3ffe:501:0:1001::2').packed
        prev = ipv6(6, 0, 0, len(buf), 64, 255, src_ipv6, dst_ipv6)
        echo_csum = icmpv6_csum(prev, buf)

        echo = icmpv6.echo(self.id_, self.seq, echo_data)
        icmp = icmpv6.icmpv6(self.type_, self.code, 0, echo)
        buf = buffer(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (id_, seq) = struct.unpack_from(echo._PACK_STR, buf, icmp._MIN_LEN)
        data = buf[(icmp._MIN_LEN + echo._MIN_LEN):]
        data = data if len(data) != 0 else None

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, echo_csum)
        eq_(id_, self.id_)
        eq_(seq, self.seq)
        eq_(data, echo_data)

    def test_serialize_without_data(self):
        self._test_serialize()

    def test_serialize_with_data(self):
        self._test_serialize(self.data)


class Test_icmpv6_echo_reply(Test_icmpv6_echo_request):
    def setUp(self):
        self.type_ = 129
        self.csum = 0xa472
        self.buf = '\x81\x00\xa4\x72\x76\x20\x00\x00'


class Test_icmpv6_neighbor_solict(unittest.TestCase):
    type_ = 135
    code = 0
    csum = 0x952d
    res = 0
    dst = netaddr.IPAddress('3ffe:507:0:1:200:86ff:fe05:80da').packed
    nd_type = 1
    nd_length = 1
    nd_hw_src = '\x00\x60\x97\x07\x69\xea'
    data = '\x01\x01\x00\x60\x97\x07\x69\xea'
    buf = '\x87\x00\x95\x2d\x00\x00\x00\x00' \
        + '\x3f\xfe\x05\x07\x00\x00\x00\x01' \
        + '\x02\x00\x86\xff\xfe\x05\x80\xda'
    src_ipv6 = netaddr.IPAddress('3ffe:507:0:1:200:86ff:fe05:80da').packed
    dst_ipv6 = netaddr.IPAddress('3ffe:501:0:1001::2').packed

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        nd = icmpv6.nd_neighbor(self.res, self.dst)
        eq_(nd.res >> 29, self.res)
        eq_(nd.dst, self.dst)
        eq_(nd.type_, None)
        eq_(nd.length, None)
        eq_(nd.data, None)

    def _test_parser(self, data=None):
        buf = self.buf + str(data or '')
        msg, n = icmpv6.icmpv6.parser(buf)

        eq_(msg.type_, self.type_)
        eq_(msg.code, self.code)
        eq_(msg.csum, self.csum)
        eq_(msg.data.res >> 29, self.res)
        eq_(msg.data.dst, self.dst)
        eq_(n, None)
        if data:
            nd = msg.data
            eq_(nd.type_, self.nd_type)
            eq_(nd.length, self.nd_length)
            eq_(nd.data.hw_src, self.nd_hw_src)
            eq_(nd.data.data, None)

    def test_parser_without_data(self):
        self._test_parser()

    def test_parser_with_data(self):
        self._test_parser(self.data)

    def test_serialize_without_data(self):
        nd = icmpv6.nd_neighbor(self.res, self.dst)
        prev = ipv6(6, 0, 0, 24, 64, 255, self.src_ipv6, self.dst_ipv6)
        nd_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd)
        buf = buffer(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (res, dst) = struct.unpack_from(nd._PACK_STR, buf, icmp._MIN_LEN)
        data = buf[(icmp._MIN_LEN + nd._MIN_LEN):]

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, nd_csum)
        eq_(res >> 29, self.res)
        eq_(dst, self.dst)
        eq_(data, '')

    def test_serialize_with_data(self):
        nd_opt = icmpv6.nd_option_la(self.nd_hw_src)
        nd = icmpv6.nd_neighbor(
            self.res, self.dst, self.nd_type, self.nd_length, nd_opt)
        prev = ipv6(6, 0, 0, 32, 64, 255, self.src_ipv6, self.dst_ipv6)
        nd_csum = icmpv6_csum(prev, self.buf + self.data)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd)
        buf = buffer(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (res, dst) = struct.unpack_from(nd._PACK_STR, buf, icmp._MIN_LEN)
        (nd_type, nd_length, nd_hw_src) = struct.unpack_from(
            '!BB6s', buf, icmp._MIN_LEN + nd._MIN_LEN)
        data = buf[(icmp._MIN_LEN + nd._MIN_LEN + 8):]

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, nd_csum)
        eq_(res >> 29, self.res)
        eq_(dst, self.dst)
        eq_(nd_type, self.nd_type)
        eq_(nd_length, self.nd_length)
        eq_(nd_hw_src, self.nd_hw_src)


class Test_icmpv6_neighbor_advert(Test_icmpv6_neighbor_solict):
    def setUp(self):
        self.type_ = 136
        self.csum = 0xb8ba
        self.res = 7
        self.dst = netaddr.IPAddress('3ffe:507:0:1:260:97ff:fe07:69ea').packed
        self.nd_type = 2
        self.nd_length = 1
        self.nd_data = None
        self.nd_hw_src = '\x00\x60\x97\x07\x69\xea'
        self.data = '\x02\x01\x00\x60\x97\x07\x69\xea'
        self.buf = '\x88\x00\xb8\xba\xe0\x00\x00\x00' \
            + '\x3f\xfe\x05\x07\x00\x00\x00\x01' \
            + '\x02\x60\x97\xff\xfe\x07\x69\xea'


class Test_icmpv6_router_solict(unittest.TestCase):
    type_ = 133
    code = 0
    csum = 0x97d9
    res = 0
    nd_type = 1
    nd_length = 1
    nd_data = None
    nd_hw_src = '\x12\x2d\xa5\x6d\xbc\x0f'
    data = '\x00\x00\x00\x00\x01\x01\x12\x2d\xa5\x6d\xbc\x0f'
    buf = '\x85\x00\x97\xd9'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def _test_parser(self, data=None):
        buf = self.buf + str(data or '')
        msg, n = icmpv6.icmpv6.parser(buf)

        eq_(msg.type_, self.type_)
        eq_(msg.code, self.code)
        eq_(msg.csum, self.csum)
        eq_(msg.data, data)

    def test_parser_without_data(self):
        self._test_parser()

    def test_parser_with_data(self):
        self._test_parser(self.data)

    def _test_serialize(self, nd_data=None):
        nd_data = str(nd_data or '')
        buf = self.buf + nd_data
        src_ipv6 = netaddr.IPAddress('fe80::102d:a5ff:fe6d:bc0f').packed
        dst_ipv6 = netaddr.IPAddress('ff02::2').packed
        prev = ipv6(6, 0, 0, len(buf), 58, 255, src_ipv6, dst_ipv6)
        nd_csum = icmpv6_csum(prev, buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd_data)
        buf = buffer(icmp.serialize(bytearray(), prev))
        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        data = buf[icmp._MIN_LEN:]

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, nd_csum)
        eq_(data, nd_data)

    def test_serialize_without_data(self):
        self._test_serialize()

    def test_serialize_with_data(self):
        self._test_serialize(self.data)
