# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

from __future__ import print_function

import logging
import struct
import unittest

from nose.tools import eq_
from nose.tools import raises

from ryu.lib import ip

LOG = logging.getLogger('test_ip')


class Test_ip(unittest.TestCase):
    """
    test case for ip address module
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_ipv4_to_bin(self):
        ipv4_str = '10.28.197.1'
        val = 0x0a1cc501

        (res,) = struct.unpack('!I', ip.ipv4_to_bin(ipv4_str))
        eq_(val, res)

    def test_ipv4_to_int(self):
        ipv4_str = '10.28.197.1'
        val = 169657601

        res = ip.ipv4_to_int(ipv4_str)
        eq_(val, res)

    def test_ipv4_to_str_from_bin(self):
        ipv4_bin = struct.pack('!I', 0x0a1cc501)
        val = '10.28.197.1'

        res = ip.ipv4_to_str(ipv4_bin)
        eq_(val, res)

    def test_ipv4_to_str_from_int(self):
        ipv4_int = 169657601
        val = '10.28.197.1'

        res = ip.ipv4_to_str(ipv4_int)
        eq_(val, res)

    def test_ipv6_to_bin(self):
        ipv6_str = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'
        val = struct.pack('!8H', 0x2013, 0xda8, 0x215, 0x8f2, 0xaa20, 0x66ff,
                          0xfe4c, 0x9c3c)
        res = ip.ipv6_to_bin(ipv6_str)
        eq_(val, res)

    def test_ipv6_to_bin_with_shortcut(self):
        ipv6_str = '3f:10::1:2'
        val = struct.pack('!8H', 0x3f, 0x10, 0, 0, 0, 0, 0x1, 0x2)

        res = ip.ipv6_to_bin(ipv6_str)
        eq_(val, res)

    def test_ipv6_to_int(self):
        ipv6_str = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'
        val = 0x20130da8021508f2aa2066fffe4c9c3c

        res = ip.ipv6_to_int(ipv6_str)
        eq_(val, res)

    def test_ipv6_to_int_with_shortcut(self):
        ipv6_str = '3f:10::1:2'
        val = 0x003f0010000000000000000000010002

        res = ip.ipv6_to_int(ipv6_str)
        eq_(val, res)

    def test_ipv6_to_str_from_bin(self):
        ipv6_bin = struct.pack('!8H', 0x2013, 0xda8, 0x215, 0x8f2, 0xaa20,
                               0x66ff, 0xfe4c, 0x9c3c)
        val = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'

        res = ip.ipv6_to_str(ipv6_bin)
        eq_(val, res)

    def test_ipv6_to_str_from_int(self):
        ipv6_int = 0x20130da8021508f2aa2066fffe4c9c3c
        val = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'

        res = ip.ipv6_to_str(ipv6_int)
        eq_(val, res)

    def test_text_to_bin_from_ipv4_text(self):
        ipv4_str = '10.28.197.1'
        val = struct.pack('!4B', 10, 28, 197, 1)
        res = ip.text_to_bin(ipv4_str)
        eq_(val, res)

    def test_text_to_bin_from_ipv6_text(self):
        ipv6_str = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'
        val = struct.pack('!8H', 0x2013, 0xda8, 0x215, 0x8f2, 0xaa20,
                          0x66ff, 0xfe4c, 0x9c3c)
        res = ip.text_to_bin(ipv6_str)
        eq_(val, res)

    def test_text_to_int_from_ipv4_text(self):
        ipv4_str = '10.28.197.1'  # 0a.1c.c5.01
        val = 0x0a1cc501

        res = ip.text_to_int(ipv4_str)
        eq_(val, res)

    def test_text_to_int_from_ipv6_text(self):
        ipv6_str = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'
        val = 0x20130da8021508f2aa2066fffe4c9c3c

        res = ip.text_to_int(ipv6_str)
        eq_(val, res)

    def test_bin_to_text_from_ipv4_bin(self):
        ipv4_bin = struct.pack('!4B', 10, 28, 197, 1)
        val = '10.28.197.1'
        res = ip.bin_to_text(ipv4_bin)
        eq_(val, res)

    def test_bin_to_text_from_ipv6_bin(self):
        ipv6_bin = struct.pack('!8H', 0x2013, 0xda8, 0x215, 0x8f2, 0xaa20,
                               0x66ff, 0xfe4c, 0x9c3c)
        val = '2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'
        res = ip.bin_to_text(ipv6_bin)
        eq_(val, res)

    @raises(struct.error)
    def test_bin_to_text_with_invalid_bin(self):
        invalid_bin = b'invalid'

        ip.bin_to_text(invalid_bin)
