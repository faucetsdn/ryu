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
from nose.tools import eq_
from ryu.ofproto.ether import *


LOG = logging.getLogger('test_ether')


class TestInet(unittest.TestCase):
    """ Test case for ether
    """

    def test_ether_type(self):
        eq_(ETH_TYPE_IP, 0x0800)
        eq_(ETH_TYPE_ARP, 0x0806)
        eq_(ETH_TYPE_8021Q, 0x8100)
        eq_(ETH_TYPE_IPV6, 0x86dd)
        eq_(ETH_TYPE_MPLS, 0x8847)
        eq_(ETH_TYPE_SLOW, 0x8809)
