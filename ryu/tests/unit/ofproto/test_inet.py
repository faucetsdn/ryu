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
from ryu.ofproto.inet import *


LOG = logging.getLogger('test_inet')


class TestInet(unittest.TestCase):
    """ Test case for inet
    """

    def test_ip_proto(self):
        eq_(IPPROTO_IP, 0)
        eq_(IPPROTO_HOPOPTS, 0)
        eq_(IPPROTO_ICMP, 1)
        eq_(IPPROTO_TCP, 6)
        eq_(IPPROTO_UDP, 17)
        eq_(IPPROTO_ROUTING, 43)
        eq_(IPPROTO_FRAGMENT, 44)
        eq_(IPPROTO_AH, 51)
        eq_(IPPROTO_ICMPV6, 58)
        eq_(IPPROTO_NONE, 59)
        eq_(IPPROTO_DSTOPTS, 60)
        eq_(IPPROTO_SCTP, 132)
