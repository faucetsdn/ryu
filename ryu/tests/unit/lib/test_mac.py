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

from ryu.lib import mac

LOG = logging.getLogger('test_mac')


class Test_mac(unittest.TestCase):
    """ Test case for mac
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_mac_is_multicast(self):
        addr = '\x01\x23\x45\x67\x89\x0a'
        val = True

        res = mac.is_multicast(addr)

        eq_(val, res)

    def test_mac_haddr_to_str(self):
        addr = 'aa:aa:aa:aa:aa:aa'
        val = '\xaa\xaa\xaa\xaa\xaa\xaa'

        res = mac.haddr_to_str(val)

        eq_(addr, res)

    def test_mac_haddr_to_str_none(self):
        """ addr is None
        """
        addr = None
        val = 'None'
        res = mac.haddr_to_str(addr)

        eq_(val, res)

    @raises(AssertionError)
    def test_mac_haddr_to_str_assert(self):
        val = '\xaa\xaa\xaa\xaa\xaa'

        res = mac.haddr_to_str(val)

    def test_mac_haddr_to_bin_false(self):
        """ len(hexes) = 6 (False)
        """
        addr = 'aa:aa:aa:aa:aa:aa'
        val = '\xaa\xaa\xaa\xaa\xaa\xaa'

        res = mac.haddr_to_bin(addr)

        eq_(val, res)

    @raises(ValueError)
    def test_mac_haddr_to_bin_true(self):
        """ len(hexes) != 6 (True)
        """
        addr = 'aa:aa:aa:aa:aa'
        res = mac.haddr_to_bin(addr)

    def test_mac_haddr_bitand(self):
        addr = '\xaa\xaa\xaa\xaa\xaa\xaa'
        mask = '\xff\xff\xff\x00\x00\x00'
        val = '\xaa\xaa\xaa\x00\x00\x00'

        res = mac.haddr_bitand(addr, mask)

        eq_(val, res)
