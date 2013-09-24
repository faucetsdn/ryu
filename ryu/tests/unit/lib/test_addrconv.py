# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import unittest
from nose.tools import eq_

import addrconv


class Test_addrconv(unittest.TestCase):
    """ Test case for ryu.lib.addrconv
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @staticmethod
    def _test_conv(conv, text_value, bin_value):
        eq_(conv.text_to_bin(text_value), bin_value)
        eq_(conv.bin_to_text(bin_value), text_value)

    def test_ipv4(self):
        self._test_conv(addrconv.ipv4, '0.0.0.0', '\x00\x00\x00\x00')
        self._test_conv(addrconv.ipv4, '127.0.0.1', '\x7f\x00\x00\x01')
        self._test_conv(addrconv.ipv4, '255.255.0.0', '\xff\xff\x00\x00')

    def test_ipv6(self):
        self._test_conv(addrconv.ipv6, 'ff02::1',
                        ('\xff\x02\x00\x00\x00\x00\x00\x00'
                         '\x00\x00\x00\x00\x00\x00\x00\x01'))
        self._test_conv(addrconv.ipv6, 'fe80::f00b:a4ff:fe7d:f8ea',
                        ('\xfe\x80\x00\x00\x00\x00\x00\x00'
                         '\xf0\x0b\xa4\xff\xfe\x7d\xf8\xea'))
        self._test_conv(addrconv.ipv6, '::',
                        ('\x00\x00\x00\x00\x00\x00\x00\x00'
                         '\x00\x00\x00\x00\x00\x00\x00\x00'))

    def test_mac(self):
        self._test_conv(addrconv.mac, 'f2:0b:a4:01:0a:23',
                        '\xf2\x0b\xa4\x01\x0a\x23')
