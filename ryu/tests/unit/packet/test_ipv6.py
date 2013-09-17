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

    def test_len(self):
        eq_(len(self.ip), 40)
