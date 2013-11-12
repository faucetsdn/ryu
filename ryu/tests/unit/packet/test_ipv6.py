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


import unittest
import logging
import inspect
import struct

from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.lib import addrconv
from ryu.lib import ip
from ryu.lib.packet import ipv6


LOG = logging.getLogger(__name__)


class Test_ipv6(unittest.TestCase):

    def setUp(self):
        self.version = 6
        self.traffic_class = 0
        self.flow_label = 0
        self.payload_length = 817
        self.nxt = 6
        self.hop_limit = 128
        self.src = '2002:4637:d5d3::4637:d5d3'
        self.dst = '2001:4860:0:2001::68'
        self.ext_hdrs = []
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)

        self.v_tc_flow = (
            self.version << 28 | self.traffic_class << 20 |
            self.flow_label << 12)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))

    def setUp_with_hop_opts(self):
        self.opt1_type = 5
        self.opt1_len = 2
        self.opt1_data = '\x00\x00'
        self.opt2_type = 1
        self.opt2_len = 0
        self.opt2_data = None
        self.options = [
            ipv6.option(self.opt1_type, self.opt1_len, self.opt1_data),
            ipv6.option(self.opt2_type, self.opt2_len, self.opt2_data),
        ]
        self.hop_opts_nxt = 6
        self.hop_opts_size = 0
        self.hop_opts = ipv6.hop_opts(
            self.hop_opts_nxt, self.hop_opts_size, self.options)
        self.ext_hdrs = [self.hop_opts]
        self.payload_length += len(self.hop_opts)
        self.nxt = ipv6.hop_opts.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.hop_opts.serialize()

    def setUp_with_dst_opts(self):
        self.opt1_type = 5
        self.opt1_len = 2
        self.opt1_data = '\x00\x00'
        self.opt2_type = 1
        self.opt2_len = 0
        self.opt2_data = None
        self.options = [
            ipv6.option(self.opt1_type, self.opt1_len, self.opt1_data),
            ipv6.option(self.opt2_type, self.opt2_len, self.opt2_data),
        ]
        self.dst_opts_nxt = 6
        self.dst_opts_size = 0
        self.dst_opts = ipv6.dst_opts(
            self.dst_opts_nxt, self.dst_opts_size, self.options)
        self.ext_hdrs = [self.dst_opts]
        self.payload_length += len(self.dst_opts)
        self.nxt = ipv6.dst_opts.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.dst_opts.serialize()

    def setUp_with_fragment(self):
        self.fragment_nxt = 6
        self.fragment_offset = 50
        self.fragment_more = 1
        self.fragment_id = 123
        self.fragment = ipv6.fragment(
            self.fragment_nxt, self.fragment_offset, self.fragment_more,
            self.fragment_id)
        self.ext_hdrs = [self.fragment]
        self.payload_length += len(self.fragment)
        self.nxt = ipv6.fragment.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.fragment.serialize()

    def setUp_with_auth(self):
        self.auth_nxt = 6
        self.auth_size = 4
        self.auth_spi = 256
        self.auth_seq = 1
        self.auth_data = '\xa0\xe7\xf8\xab\xf9\x69\x1a\x8b\xf3\x9f\x7c\xae'
        self.auth = ipv6.auth(
            self.auth_nxt, self.auth_size, self.auth_spi, self.auth_seq,
            self.auth_data)
        self.ext_hdrs = [self.auth]
        self.payload_length += len(self.auth)
        self.nxt = ipv6.auth.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.auth.serialize()

    def setUp_with_multi_headers(self):
        self.opt1_type = 5
        self.opt1_len = 2
        self.opt1_data = '\x00\x00'
        self.opt2_type = 1
        self.opt2_len = 0
        self.opt2_data = None
        self.options = [
            ipv6.option(self.opt1_type, self.opt1_len, self.opt1_data),
            ipv6.option(self.opt2_type, self.opt2_len, self.opt2_data),
        ]
        self.hop_opts_nxt = ipv6.auth.TYPE
        self.hop_opts_size = 0
        self.hop_opts = ipv6.hop_opts(
            self.hop_opts_nxt, self.hop_opts_size, self.options)
        self.auth_nxt = 6
        self.auth_size = 4
        self.auth_spi = 256
        self.auth_seq = 1
        self.auth_data = '\xa0\xe7\xf8\xab\xf9\x69\x1a\x8b\xf3\x9f\x7c\xae'
        self.auth = ipv6.auth(
            self.auth_nxt, self.auth_size, self.auth_spi, self.auth_seq,
            self.auth_data)
        self.ext_hdrs = [self.hop_opts, self.auth]
        self.payload_length += len(self.hop_opts) + len(self.auth)
        self.nxt = ipv6.hop_opts.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.hop_opts.serialize()
        self.buf += self.auth.serialize()

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.version, self.ip.version)
        eq_(self.traffic_class, self.ip.traffic_class)
        eq_(self.flow_label, self.ip.flow_label)
        eq_(self.payload_length, self.ip.payload_length)
        eq_(self.nxt, self.ip.nxt)
        eq_(self.hop_limit, self.ip.hop_limit)
        eq_(self.src, self.ip.src)
        eq_(self.dst, self.ip.dst)
        eq_(str(self.ext_hdrs), str(self.ip.ext_hdrs))

    def test_init_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_init()

    def test_init_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_init()

    def test_init_with_fragment(self):
        self.setUp_with_fragment()
        self.test_init()

    def test_init_with_auth(self):
        self.setUp_with_auth()
        self.test_init()

    def test_init_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_init()

    def test_parser(self):
        _res = self.ip.parser(str(self.buf))
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        eq_(self.version, res.version)
        eq_(self.traffic_class, res.traffic_class)
        eq_(self.flow_label, res.flow_label)
        eq_(self.payload_length, res.payload_length)
        eq_(self.nxt, res.nxt)
        eq_(self.hop_limit, res.hop_limit)
        eq_(self.src, res.src)
        eq_(self.dst, res.dst)
        eq_(str(self.ext_hdrs), str(res.ext_hdrs))

    def test_parser_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_parser()

    def test_parser_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_parser()

    def test_parser_with_fragment(self):
        self.setUp_with_fragment()
        self.test_parser()

    def test_parser_with_auth(self):
        self.setUp_with_auth()
        self.test_parser()

    def test_parser_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_parser()

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)

        res = struct.unpack_from(ipv6.ipv6._PACK_STR, str(buf))

        eq_(self.v_tc_flow, res[0])
        eq_(self.payload_length, res[1])
        eq_(self.nxt, res[2])
        eq_(self.hop_limit, res[3])
        eq_(self.src, addrconv.ipv6.bin_to_text(res[4]))
        eq_(self.dst, addrconv.ipv6.bin_to_text(res[5]))

    def test_serialize_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        hop_opts = ipv6.hop_opts.parser(str(buf[ipv6.ipv6._MIN_LEN:]))
        eq_(repr(self.hop_opts), repr(hop_opts))

    def test_serialize_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        dst_opts = ipv6.dst_opts.parser(str(buf[ipv6.ipv6._MIN_LEN:]))
        eq_(repr(self.dst_opts), repr(dst_opts))

    def test_serialize_with_fragment(self):
        self.setUp_with_fragment()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        fragment = ipv6.fragment.parser(str(buf[ipv6.ipv6._MIN_LEN:]))
        eq_(repr(self.fragment), repr(fragment))

    def test_serialize_with_auth(self):
        self.setUp_with_auth()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        auth = ipv6.auth.parser(str(buf[ipv6.ipv6._MIN_LEN:]))
        eq_(repr(self.auth), repr(auth))

    def test_serialize_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        offset = ipv6.ipv6._MIN_LEN
        hop_opts = ipv6.hop_opts.parser(str(buf[offset:]))
        offset += len(hop_opts)
        auth = ipv6.auth.parser(str(buf[offset:]))
        eq_(repr(self.hop_opts), repr(hop_opts))
        eq_(repr(self.auth), repr(auth))

    def test_to_string(self):
        ipv6_values = {'version': self.version,
                       'traffic_class': self.traffic_class,
                       'flow_label': self.flow_label,
                       'payload_length': self.payload_length,
                       'nxt': self.nxt,
                       'hop_limit': self.hop_limit,
                       'src': repr(self.src),
                       'dst': repr(self.dst),
                       'ext_hdrs': self.ext_hdrs}
        _ipv6_str = ','.join(['%s=%s' % (k, ipv6_values[k])
                              for k, v in inspect.getmembers(self.ip)
                              if k in ipv6_values])
        ipv6_str = '%s(%s)' % (ipv6.ipv6.__name__, _ipv6_str)

        eq_(str(self.ip), ipv6_str)
        eq_(repr(self.ip), ipv6_str)

    def test_to_string_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_to_string()

    def test_to_string_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_to_string()

    def test_to_string_with_fragment(self):
        self.setUp_with_fragment()
        self.test_to_string()

    def test_to_string_with_auth(self):
        self.setUp_with_auth()
        self.test_to_string()

    def test_to_string_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_to_string()

    def test_len(self):
        eq_(len(self.ip), 40)

    def test_len_with_hop_opts(self):
        self.setUp_with_hop_opts()
        eq_(len(self.ip), 40 + len(self.hop_opts))

    def test_len_with_dst_opts(self):
        self.setUp_with_dst_opts()
        eq_(len(self.ip), 40 + len(self.dst_opts))

    def test_len_with_fragment(self):
        self.setUp_with_fragment()
        eq_(len(self.ip), 40 + len(self.fragment))

    def test_len_with_auth(self):
        self.setUp_with_auth()
        eq_(len(self.ip), 40 + len(self.auth))

    def test_len_with_multi_headers(self):
        self.setUp_with_multi_headers()
        eq_(len(self.ip), 40 + len(self.hop_opts) + len(self.auth))

    def test_default_args(self):
        ip = ipv6.ipv6()
        buf = ip.serialize(bytearray(), None)
        res = struct.unpack(ipv6.ipv6._PACK_STR, str(buf))

        eq_(res[0], 6 << 28)
        eq_(res[1], 0)
        eq_(res[2], 6)
        eq_(res[3], 255)
        eq_(res[4], addrconv.ipv6.text_to_bin('::'))
        eq_(res[5], addrconv.ipv6.text_to_bin('::'))

        # with extension header
        ip = ipv6.ipv6(
            nxt=0, ext_hdrs=[
                ipv6.hop_opts(58, 0, [
                    ipv6.option(5, 2, '\x00\x00'),
                    ipv6.option(1, 0, None)])])
        buf = ip.serialize(bytearray(), None)
        res = struct.unpack(ipv6.ipv6._PACK_STR + '8s', str(buf))

        eq_(res[0], 6 << 28)
        eq_(res[1], 8)
        eq_(res[2], 0)
        eq_(res[3], 255)
        eq_(res[4], addrconv.ipv6.text_to_bin('::'))
        eq_(res[5], addrconv.ipv6.text_to_bin('::'))
        eq_(res[6], '\x3a\x00\x05\x02\x00\x00\x01\x00')


class Test_hop_opts(unittest.TestCase):

    def setUp(self):
        self.nxt = 0
        self.size = 8
        self.data = [
            ipv6.option(5, 2, '\x00\x00'),
            ipv6.option(1, 0, None),
            ipv6.option(0xc2, 4, '\x00\x01\x00\x00'),
            ipv6.option(1, 0, None),
        ]
        self.hop = ipv6.hop_opts(self.nxt, self.size, self.data)
        self.form = '!BB'
        self.buf = struct.pack(self.form, self.nxt, self.size) \
            + self.data[0].serialize() \
            + self.data[1].serialize() \
            + self.data[2].serialize() \
            + self.data[3].serialize()

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.nxt, self.hop.nxt)
        eq_(self.size, self.hop.size)
        eq_(self.data, self.hop.data)

    @raises(Exception)
    def test_invalid_size(self):
        ipv6.hop_opts(self.nxt, 1, self.data)

    def test_parser(self):
        _res = ipv6.hop_opts.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.nxt, res.nxt)
        eq_(self.size, res.size)
        eq_(str(self.data), str(res.data))

    def test_serialize(self):
        buf = self.hop.serialize()
        res = struct.unpack_from(self.form, str(buf))
        eq_(self.nxt, res[0])
        eq_(self.size, res[1])
        offset = struct.calcsize(self.form)
        opt1 = ipv6.option.parser(str(buf[offset:]))
        offset += len(opt1)
        opt2 = ipv6.option.parser(str(buf[offset:]))
        offset += len(opt2)
        opt3 = ipv6.option.parser(str(buf[offset:]))
        offset += len(opt3)
        opt4 = ipv6.option.parser(str(buf[offset:]))
        eq_(5, opt1.type_)
        eq_(2, opt1.len_)
        eq_('\x00\x00', opt1.data)
        eq_(1, opt2.type_)
        eq_(0, opt2.len_)
        eq_(None, opt2.data)
        eq_(0xc2, opt3.type_)
        eq_(4, opt3.len_)
        eq_('\x00\x01\x00\x00', opt3.data)
        eq_(1, opt4.type_)
        eq_(0, opt4.len_)
        eq_(None, opt4.data)

    def test_len(self):
        eq_(16, len(self.hop))

    def test_default_args(self):
        hdr = ipv6.hop_opts()
        buf = hdr.serialize()
        res = struct.unpack('!BB', str(buf[:2]))

        eq_(res[0], 6)
        eq_(res[1], 0)
        opt = ipv6.option(type_=1, len_=6, data='\x00\x00\x00\x00\x00\x00')
        eq_(str(buf[2:]), opt.serialize())


class Test_dst_opts(unittest.TestCase):

    def setUp(self):
        self.nxt = 60
        self.size = 8
        self.data = [
            ipv6.option(5, 2, '\x00\x00'),
            ipv6.option(1, 0, None),
            ipv6.option(0xc2, 4, '\x00\x01\x00\x00'),
            ipv6.option(1, 0, None),
        ]
        self.dst = ipv6.dst_opts(self.nxt, self.size, self.data)
        self.form = '!BB'
        self.buf = struct.pack(self.form, self.nxt, self.size) \
            + self.data[0].serialize() \
            + self.data[1].serialize() \
            + self.data[2].serialize() \
            + self.data[3].serialize()

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.nxt, self.dst.nxt)
        eq_(self.size, self.dst.size)
        eq_(self.data, self.dst.data)

    @raises(Exception)
    def test_invalid_size(self):
        ipv6.dst_opts(self.nxt, 1, self.data)

    def test_parser(self):
        _res = ipv6.dst_opts.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.nxt, res.nxt)
        eq_(self.size, res.size)
        eq_(str(self.data), str(res.data))

    def test_serialize(self):
        buf = self.dst.serialize()
        res = struct.unpack_from(self.form, str(buf))
        eq_(self.nxt, res[0])
        eq_(self.size, res[1])
        offset = struct.calcsize(self.form)
        opt1 = ipv6.option.parser(str(buf[offset:]))
        offset += len(opt1)
        opt2 = ipv6.option.parser(str(buf[offset:]))
        offset += len(opt2)
        opt3 = ipv6.option.parser(str(buf[offset:]))
        offset += len(opt3)
        opt4 = ipv6.option.parser(str(buf[offset:]))
        eq_(5, opt1.type_)
        eq_(2, opt1.len_)
        eq_('\x00\x00', opt1.data)
        eq_(1, opt2.type_)
        eq_(0, opt2.len_)
        eq_(None, opt2.data)
        eq_(0xc2, opt3.type_)
        eq_(4, opt3.len_)
        eq_('\x00\x01\x00\x00', opt3.data)
        eq_(1, opt4.type_)
        eq_(0, opt4.len_)
        eq_(None, opt4.data)

    def test_len(self):
        eq_(16, len(self.dst))

    def test_default_args(self):
        hdr = ipv6.dst_opts()
        buf = hdr.serialize()
        res = struct.unpack('!BB', str(buf[:2]))

        eq_(res[0], 6)
        eq_(res[1], 0)
        opt = ipv6.option(type_=1, len_=6, data='\x00\x00\x00\x00\x00\x00')
        eq_(str(buf[2:]), opt.serialize())


class Test_option(unittest.TestCase):

    def setUp(self):
        self.type_ = 5
        self.data = '\x00\x00'
        self.len_ = len(self.data)
        self.opt = ipv6.option(self.type_, self.len_, self.data)
        self.form = '!BB%ds' % self.len_
        self.buf = struct.pack(self.form, self.type_, self.len_, self.data)

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.type_, self.opt.type_)
        eq_(self.len_, self.opt.len_)
        eq_(self.data, self.opt.data)

    def test_parser(self):
        _res = ipv6.option.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.type_, res.type_)
        eq_(self.len_, res.len_)
        eq_(self.data, res.data)

    def test_serialize(self):
        buf = self.opt.serialize()
        res = struct.unpack_from(self.form, buf)
        eq_(self.type_, res[0])
        eq_(self.len_, res[1])
        eq_(self.data, res[2])

    def test_len(self):
        eq_(len(self.opt), 2 + self.len_)


class Test_option_pad1(Test_option):

    def setUp(self):
        self.type_ = 0
        self.len_ = -1
        self.data = None
        self.opt = ipv6.option(self.type_, self.len_, self.data)
        self.form = '!B'
        self.buf = struct.pack(self.form, self.type_)

    def test_serialize(self):
        buf = self.opt.serialize()
        res = struct.unpack_from(self.form, buf)
        eq_(self.type_, res[0])

    def test_default_args(self):
        opt = ipv6.option()
        buf = opt.serialize()
        res = struct.unpack('!B', buf)

        eq_(res[0], 0)


class Test_option_padN(Test_option):

    def setUp(self):
        self.type_ = 1
        self.len_ = 0
        self.data = None
        self.opt = ipv6.option(self.type_, self.len_, self.data)
        self.form = '!BB'
        self.buf = struct.pack(self.form, self.type_, self.len_)

    def test_serialize(self):
        buf = self.opt.serialize()
        res = struct.unpack_from(self.form, buf)
        eq_(self.type_, res[0])
        eq_(self.len_, res[1])


class Test_fragment(unittest.TestCase):

    def setUp(self):
        self.nxt = 44
        self.offset = 50
        self.more = 1
        self.id_ = 123
        self.fragment = ipv6.fragment(
            self.nxt, self.offset, self.more, self.id_)

        self.off_m = (self.offset << 3 | self.more)
        self.form = '!BxHI'
        self.buf = struct.pack(self.form, self.nxt, self.off_m, self.id_)

    def test_init(self):
        eq_(self.nxt, self.fragment.nxt)
        eq_(self.offset, self.fragment.offset)
        eq_(self.more, self.fragment.more)
        eq_(self.id_, self.fragment.id_)

    def test_parser(self):
        _res = ipv6.fragment.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.nxt, res.nxt)
        eq_(self.offset, res.offset)
        eq_(self.more, res.more)
        eq_(self.id_, res.id_)

    def test_serialize(self):
        buf = self.fragment.serialize()
        res = struct.unpack_from(self.form, str(buf))
        eq_(self.nxt, res[0])
        eq_(self.off_m, res[1])
        eq_(self.id_, res[2])

    def test_len(self):
        eq_(8, len(self.fragment))

    def test_default_args(self):
        hdr = ipv6.fragment()
        buf = hdr.serialize()
        res = struct.unpack_from(ipv6.fragment._PACK_STR, buf)

        eq_(res[0], 6)
        eq_(res[1], 0)
        eq_(res[2], 0)


class Test_auth(unittest.TestCase):

    def setUp(self):
        self.nxt = 0
        self.size = 4
        self.spi = 256
        self.seq = 1
        self.data = '\x21\xd3\xa9\x5c\x5f\xfd\x4d\x18\x46\x22\xb9\xf8'
        self.auth = ipv6.auth(
            self.nxt, self.size, self.spi, self.seq, self.data)
        self.form = '!BB2xII12s'
        self.buf = struct.pack(self.form, self.nxt, self.size, self.spi,
                               self.seq, self.data)

    def test_init(self):
        eq_(self.nxt, self.auth.nxt)
        eq_(self.size, self.auth.size)
        eq_(self.spi, self.auth.spi)
        eq_(self.seq, self.auth.seq)
        eq_(self.data, self.auth.data)

    def test_parser(self):
        _res = ipv6.auth.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        eq_(self.nxt, res.nxt)
        eq_(self.size, res.size)
        eq_(self.spi, res.spi)
        eq_(self.seq, res.seq)
        eq_(self.data, res.data)

    def test_serialize(self):
        buf = self.auth.serialize()
        res = struct.unpack_from(self.form, str(buf))
        eq_(self.nxt, res[0])
        eq_(self.size, res[1])
        eq_(self.spi, res[2])
        eq_(self.seq, res[3])
        eq_(self.data, res[4])

    def test_len(self):
        eq_((4 - 1) * 8, len(self.auth))

    def test_default_args(self):
        hdr = ipv6.auth()
        buf = hdr.serialize()
        LOG.info(repr(buf))
        res = struct.unpack_from(ipv6.auth._PACK_STR, str(buf))
        LOG.info(res)

        eq_(res[0], 6)
        eq_(res[1], 3)
        eq_(res[2], 0)
        eq_(res[3], 0)
        eq_(buf[ipv6.auth._MIN_LEN:], '\x00\x00\x00\x00')
