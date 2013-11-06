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
import inspect

from nose.tools import ok_, eq_, nottest, raises
from nose.plugins.skip import Skip, SkipTest
from ryu.ofproto import ether, inet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import icmpv6
from ryu.lib.packet.ipv6 import ipv6
from ryu.lib.packet import packet_utils
from ryu.lib import addrconv


LOG = logging.getLogger(__name__)


def icmpv6_csum(prev, buf):
    ph = struct.pack('!16s16sI3xB',
                     addrconv.ipv6.text_to_bin(prev.src),
                     addrconv.ipv6.text_to_bin(prev.dst),
                     prev.payload_length, prev.nxt)
    h = bytearray(buf)
    struct.pack_into('!H', h, 2, 0)

    return packet_utils.checksum(ph + h)


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
        msg, n, _ = self.icmp.parser(self.buf)

        eq_(msg.type_, self.type_)
        eq_(msg.code, self.code)
        eq_(msg.csum, self.csum)
        eq_(msg.data, None)
        eq_(n, None)

    def test_serialize(self):
        src_ipv6 = 'fe80::200:ff:fe00:ef'
        dst_ipv6 = 'fe80::200:ff:fe00:1'
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

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6()
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf))

        eq_(res[0], 0)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))


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
        msg, n, _ = icmpv6.icmpv6.parser(buf)

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
        src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
        dst_ipv6 = '3ffe:501:0:1001::2'
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

    def test_to_string(self):
        ec = icmpv6.echo(self.id_, self.seq, self.data)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, ec)

        echo_values = {'id': self.id_,
                       'seq': self.seq,
                       'data': self.data}
        _echo_str = ','.join(['%s=%s' % (k, repr(echo_values[k]))
                              for k, v in inspect.getmembers(ec)
                              if k in echo_values])
        echo_str = '%s(%s)' % (icmpv6.echo.__name__, _echo_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': echo_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        eq_(str(ic), ic_str)
        eq_(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_ECHO_REQUEST, data=icmpv6.echo())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ICMPV6_ECHO_REQUEST)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.echo._PACK_STR, str(buf[4:]))

        eq_(res[0], 0)
        eq_(res[1], 0)


class Test_icmpv6_echo_reply(Test_icmpv6_echo_request):
    def setUp(self):
        self.type_ = 129
        self.csum = 0xa472
        self.buf = '\x81\x00\xa4\x72\x76\x20\x00\x00'

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_ECHO_REPLY, data=icmpv6.echo())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ICMPV6_ECHO_REPLY)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.echo._PACK_STR, str(buf[4:]))

        eq_(res[0], 0)
        eq_(res[1], 0)


class Test_icmpv6_neighbor_solicit(unittest.TestCase):
    type_ = 135
    code = 0
    csum = 0x952d
    res = 0
    dst = '3ffe:507:0:1:200:86ff:fe05:80da'
    nd_type = 1
    nd_length = 1
    nd_hw_src = '00:60:97:07:69:ea'
    data = '\x01\x01\x00\x60\x97\x07\x69\xea'
    buf = '\x87\x00\x95\x2d\x00\x00\x00\x00' \
        + '\x3f\xfe\x05\x07\x00\x00\x00\x01' \
        + '\x02\x00\x86\xff\xfe\x05\x80\xda'
    src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
    dst_ipv6 = '3ffe:501:0:1001::2'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        nd = icmpv6.nd_neighbor(self.res, self.dst)
        eq_(nd.res, self.res)
        eq_(nd.dst, self.dst)
        eq_(nd.option, None)

    def _test_parser(self, data=None):
        buf = self.buf + str(data or '')
        msg, n, _ = icmpv6.icmpv6.parser(buf)

        eq_(msg.type_, self.type_)
        eq_(msg.code, self.code)
        eq_(msg.csum, self.csum)
        eq_(msg.data.res, self.res)
        eq_(addrconv.ipv6.text_to_bin(msg.data.dst),
            addrconv.ipv6.text_to_bin(self.dst))
        eq_(n, None)
        if data:
            nd = msg.data.option
            eq_(nd.length, self.nd_length)
            eq_(nd.hw_src, self.nd_hw_src)
            eq_(nd.data, None)

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
        eq_(dst, addrconv.ipv6.text_to_bin(self.dst))
        eq_(data, '')

    def test_serialize_with_data(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        prev = ipv6(6, 0, 0, 32, 64, 255, self.src_ipv6, self.dst_ipv6)
        nd_csum = icmpv6_csum(prev, self.buf + self.data)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd)
        buf = buffer(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (res, dst) = struct.unpack_from(nd._PACK_STR, buf, icmp._MIN_LEN)
        (nd_type, nd_length, nd_hw_src) = struct.unpack_from(
            nd_opt._PACK_STR, buf, icmp._MIN_LEN + nd._MIN_LEN)
        data = buf[(icmp._MIN_LEN + nd._MIN_LEN + 8):]

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, nd_csum)
        eq_(res >> 29, self.res)
        eq_(dst, addrconv.ipv6.text_to_bin(self.dst))
        eq_(nd_type, self.nd_type)
        eq_(nd_length, self.nd_length)
        eq_(nd_hw_src, addrconv.mac.text_to_bin(self.nd_hw_src))

    def test_to_string(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, nd)

        nd_opt_values = {'length': self.nd_length,
                         'hw_src': self.nd_hw_src,
                         'data': None}
        _nd_opt_str = ','.join(['%s=%s' % (k, repr(nd_opt_values[k]))
                                for k, v in inspect.getmembers(nd_opt)
                                if k in nd_opt_values])
        nd_opt_str = '%s(%s)' % (icmpv6.nd_option_sla.__name__, _nd_opt_str)

        nd_values = {'res': repr(nd.res),
                     'dst': repr(self.dst),
                     'option': nd_opt_str}
        _nd_str = ','.join(['%s=%s' % (k, nd_values[k])
                            for k, v in inspect.getmembers(nd)
                            if k in nd_values])
        nd_str = '%s(%s)' % (icmpv6.nd_neighbor.__name__, _nd_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': nd_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        eq_(str(ic), ic_str)
        eq_(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_SOLICIT, data=icmpv6.nd_neighbor())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_NEIGHBOR_SOLICIT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR, str(buf[4:]))

        eq_(res[0], 0)
        eq_(res[1], addrconv.ipv6.text_to_bin('::'))

        # with nd_option_sla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_SOLICIT,
            data=icmpv6.nd_neighbor(
                option=icmpv6.nd_option_sla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_NEIGHBOR_SOLICIT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR, str(buf[4:24]))

        eq_(res[0], 0)
        eq_(res[1], addrconv.ipv6.text_to_bin('::'))

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR, str(buf[24:]))

        eq_(res[0], icmpv6.ND_OPTION_SLA)
        eq_(res[1], len(icmpv6.nd_option_sla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_icmpv6_neighbor_advert(Test_icmpv6_neighbor_solicit):
    def setUp(self):
        self.type_ = 136
        self.csum = 0xb8ba
        self.res = 7
        self.dst = '3ffe:507:0:1:260:97ff:fe07:69ea'
        self.nd_type = 2
        self.nd_length = 1
        self.nd_data = None
        self.nd_hw_src = '00:60:97:07:69:ea'
        self.data = '\x02\x01\x00\x60\x97\x07\x69\xea'
        self.buf = '\x88\x00\xb8\xba\xe0\x00\x00\x00' \
            + '\x3f\xfe\x05\x07\x00\x00\x00\x01' \
            + '\x02\x60\x97\xff\xfe\x07\x69\xea'

    def test_serialize_with_data(self):
        nd_opt = icmpv6.nd_option_tla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        prev = ipv6(6, 0, 0, 32, 64, 255, self.src_ipv6, self.dst_ipv6)
        nd_csum = icmpv6_csum(prev, self.buf + self.data)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd)
        buf = buffer(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (res, dst) = struct.unpack_from(nd._PACK_STR, buf, icmp._MIN_LEN)
        (nd_type, nd_length, nd_hw_src) = struct.unpack_from(
            nd_opt._PACK_STR, buf, icmp._MIN_LEN + nd._MIN_LEN)
        data = buf[(icmp._MIN_LEN + nd._MIN_LEN + 8):]

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, nd_csum)
        eq_(res >> 29, self.res)
        eq_(dst, addrconv.ipv6.text_to_bin(self.dst))
        eq_(nd_type, self.nd_type)
        eq_(nd_length, self.nd_length)
        eq_(nd_hw_src, addrconv.mac.text_to_bin(self.nd_hw_src))

    def test_to_string(self):
        nd_opt = icmpv6.nd_option_tla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, nd)

        nd_opt_values = {'length': self.nd_length,
                         'hw_src': self.nd_hw_src,
                         'data': None}
        _nd_opt_str = ','.join(['%s=%s' % (k, repr(nd_opt_values[k]))
                                for k, v in inspect.getmembers(nd_opt)
                                if k in nd_opt_values])
        nd_opt_str = '%s(%s)' % (icmpv6.nd_option_tla.__name__, _nd_opt_str)

        nd_values = {'res': repr(nd.res),
                     'dst': repr(self.dst),
                     'option': nd_opt_str}
        _nd_str = ','.join(['%s=%s' % (k, nd_values[k])
                            for k, v in inspect.getmembers(nd)
                            if k in nd_values])
        nd_str = '%s(%s)' % (icmpv6.nd_neighbor.__name__, _nd_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': nd_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        eq_(str(ic), ic_str)
        eq_(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT, data=icmpv6.nd_neighbor())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_NEIGHBOR_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR, str(buf[4:]))

        eq_(res[0], 0)
        eq_(res[1], addrconv.ipv6.text_to_bin('::'))

        # with nd_option_tla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT,
            data=icmpv6.nd_neighbor(
                option=icmpv6.nd_option_tla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_NEIGHBOR_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR, str(buf[4:24]))

        eq_(res[0], 0)
        eq_(res[1], addrconv.ipv6.text_to_bin('::'))

        res = struct.unpack(icmpv6.nd_option_tla._PACK_STR, str(buf[24:]))

        eq_(res[0], icmpv6.ND_OPTION_TLA)
        eq_(res[1], len(icmpv6.nd_option_tla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_icmpv6_router_solicit(unittest.TestCase):
    type_ = 133
    code = 0
    csum = 0x97d9
    res = 0
    nd_type = 1
    nd_length = 1
    nd_hw_src = '12:2d:a5:6d:bc:0f'
    data = '\x00\x00\x00\x00\x01\x01\x12\x2d\xa5\x6d\xbc\x0f'
    buf = '\x85\x00\x97\xd9'
    src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
    dst_ipv6 = '3ffe:501:0:1001::2'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        rs = icmpv6.nd_router_solicit(self.res)
        eq_(rs.res, self.res)
        eq_(rs.option, None)

    def _test_parser(self, data=None):
        buf = self.buf + str(data or '')
        msg, n, _ = icmpv6.icmpv6.parser(buf)

        eq_(msg.type_, self.type_)
        eq_(msg.code, self.code)
        eq_(msg.csum, self.csum)
        if data is not None:
            eq_(msg.data.res, self.res)
        eq_(n, None)
        if data:
            rs = msg.data.option
            eq_(rs.length, self.nd_length)
            eq_(rs.hw_src, self.nd_hw_src)
            eq_(rs.data, None)

    def test_parser_without_data(self):
        self._test_parser()

    def test_parser_with_data(self):
        self._test_parser(self.data)

    def test_serialize_without_data(self):
        rs = icmpv6.nd_router_solicit(self.res)
        prev = ipv6(6, 0, 0, 8, 64, 255, self.src_ipv6, self.dst_ipv6)
        rs_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, rs)
        buf = buffer(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        res = struct.unpack_from(rs._PACK_STR, buf, icmp._MIN_LEN)
        data = buf[(icmp._MIN_LEN + rs._MIN_LEN):]

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, rs_csum)
        eq_(res[0], self.res)
        eq_(data, '')

    def test_serialize_with_data(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        rs = icmpv6.nd_router_solicit(self.res, nd_opt)
        prev = ipv6(6, 0, 0, 16, 64, 255, self.src_ipv6, self.dst_ipv6)
        rs_csum = icmpv6_csum(prev, self.buf + self.data)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, rs)
        buf = buffer(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        res = struct.unpack_from(rs._PACK_STR, buf, icmp._MIN_LEN)
        (nd_type, nd_length, nd_hw_src) = struct.unpack_from(
            nd_opt._PACK_STR, buf, icmp._MIN_LEN + rs._MIN_LEN)
        data = buf[(icmp._MIN_LEN + rs._MIN_LEN + 8):]

        eq_(type_, self.type_)
        eq_(code, self.code)
        eq_(csum, rs_csum)
        eq_(res[0], self.res)
        eq_(nd_type, self.nd_type)
        eq_(nd_length, self.nd_length)
        eq_(nd_hw_src, addrconv.mac.text_to_bin(self.nd_hw_src))

    def test_to_string(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        rs = icmpv6.nd_router_solicit(self.res, nd_opt)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, rs)

        nd_opt_values = {'length': self.nd_length,
                         'hw_src': self.nd_hw_src,
                         'data': None}
        _nd_opt_str = ','.join(['%s=%s' % (k, repr(nd_opt_values[k]))
                                for k, v in inspect.getmembers(nd_opt)
                                if k in nd_opt_values])
        nd_opt_str = '%s(%s)' % (icmpv6.nd_option_sla.__name__, _nd_opt_str)

        rs_values = {'res': repr(rs.res),
                     'option': nd_opt_str}
        _rs_str = ','.join(['%s=%s' % (k, rs_values[k])
                            for k, v in inspect.getmembers(rs)
                            if k in rs_values])
        rs_str = '%s(%s)' % (icmpv6.nd_router_solicit.__name__, _rs_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': rs_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        eq_(str(ic), ic_str)
        eq_(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_SOLICIT, data=icmpv6.nd_router_solicit())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_SOLICIT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_solicit._PACK_STR, str(buf[4:]))

        eq_(res[0], 0)

        # with nd_option_sla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_SOLICIT,
            data=icmpv6.nd_router_solicit(
                option=icmpv6.nd_option_sla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_SOLICIT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_solicit._PACK_STR, str(buf[4:8]))

        eq_(res[0], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR, str(buf[8:]))

        eq_(res[0], icmpv6.ND_OPTION_SLA)
        eq_(res[1], len(icmpv6.nd_option_sla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_icmpv6_router_advert(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT, data=icmpv6.nd_router_advert())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR, str(buf[4:]))

        eq_(res[0], 0)
        eq_(res[1], 0)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)

        # with nd_option_sla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_sla()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR, str(buf[4:16]))

        eq_(res[0], 0)
        eq_(res[1], 0)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR, str(buf[16:]))

        eq_(res[0], icmpv6.ND_OPTION_SLA)
        eq_(res[1], len(icmpv6.nd_option_sla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        # with nd_option_pi
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_pi()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR, str(buf[4:16]))

        eq_(res[0], 0)
        eq_(res[1], 0)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR, str(buf[16:]))

        eq_(res[0], icmpv6.ND_OPTION_PI)
        eq_(res[1], 4)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)
        eq_(res[5], 0)
        eq_(res[6], 0)
        eq_(res[7], addrconv.ipv6.text_to_bin('::'))

        # with nd_option_sla and nd_option_pi
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_sla(), icmpv6.nd_option_pi()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR, str(buf[4:16]))

        eq_(res[0], 0)
        eq_(res[1], 0)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR, str(buf[16:24]))

        eq_(res[0], icmpv6.ND_OPTION_SLA)
        eq_(res[1], len(icmpv6.nd_option_sla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR, str(buf[24:]))

        eq_(res[0], icmpv6.ND_OPTION_PI)
        eq_(res[1], len(icmpv6.nd_option_pi()) / 8)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)
        eq_(res[5], 0)
        eq_(res[6], 0)
        eq_(res[7], addrconv.ipv6.text_to_bin('::'))


class Test_icmpv6_nd_option_la(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_default_args(self):
        la = icmpv6.nd_option_sla()
        buf = la.serialize()
        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR, str(buf))

        eq_(res[0], icmpv6.ND_OPTION_SLA)
        eq_(res[1], len(icmpv6.nd_option_sla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        # with nd_neighbor
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT,
            data=icmpv6.nd_neighbor(
                option=icmpv6.nd_option_tla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_NEIGHBOR_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR, str(buf[4:24]))

        eq_(res[0], 0)
        eq_(res[1], addrconv.ipv6.text_to_bin('::'))

        res = struct.unpack(icmpv6.nd_option_tla._PACK_STR, str(buf[24:]))

        eq_(res[0], icmpv6.ND_OPTION_TLA)
        eq_(res[1], len(icmpv6.nd_option_tla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        # with nd_router_solicit
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_SOLICIT,
            data=icmpv6.nd_router_solicit(
                option=icmpv6.nd_option_sla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_SOLICIT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_solicit._PACK_STR, str(buf[4:8]))

        eq_(res[0], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR, str(buf[8:]))

        eq_(res[0], icmpv6.ND_OPTION_SLA)
        eq_(res[1], len(icmpv6.nd_option_sla()) / 8)
        eq_(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_icmpv6_nd_option_pi(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_default_args(self):
        pi = icmpv6.nd_option_pi()
        buf = pi.serialize()
        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR, str(buf))

        eq_(res[0], icmpv6.ND_OPTION_PI)
        eq_(res[1], len(icmpv6.nd_option_pi()) / 8)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)
        eq_(res[5], 0)
        eq_(res[6], 0)
        eq_(res[7], addrconv.ipv6.text_to_bin('::'))

        # with nd_router_advert
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_pi()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, str(buf[:4]))

        eq_(res[0], icmpv6.ND_ROUTER_ADVERT)
        eq_(res[1], 0)
        eq_(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR, str(buf[4:16]))

        eq_(res[0], 0)
        eq_(res[1], 0)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR, str(buf[16:]))

        eq_(res[0], icmpv6.ND_OPTION_PI)
        eq_(res[1], 4)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(res[4], 0)
        eq_(res[5], 0)
        eq_(res[6], 0)
        eq_(res[7], addrconv.ipv6.text_to_bin('::'))
