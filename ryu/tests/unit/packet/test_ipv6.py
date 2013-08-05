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

from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.lib import ip
from ryu.lib.packet import ipv6


LOG = logging.getLogger(__name__)


class Test_ipv6(unittest.TestCase):

    version = 6
    traffic_class = 0
    flow_label = 0
    payload_length = 817
    nxt = 6
    hop_limit = 128
    src = ip.ipv6_to_bin('2002:4637:d5d3::4637:d5d3')
    dst = ip.ipv6_to_bin('2001:4860:0:2001::68')

    ip = ipv6.ipv6(version, traffic_class, flow_label, payload_length,
                   nxt, hop_limit, src, dst)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_to_string(self):
        ipv6_values = {'version': self.version,
                       'traffic_class': self.traffic_class,
                       'flow_label': self.flow_label,
                       'payload_length': self.payload_length,
                       'nxt': self.nxt,
                       'hop_limit': self.hop_limit,
                       'src': self.src,
                       'dst': self.dst}
        _ipv6_str = ','.join(['%s=%s' % (k, repr(ipv6_values[k]))
                              for k, v in inspect.getmembers(self.ip)
                              if k in ipv6_values])
        ipv6_str = '%s(%s)' % (ipv6.ipv6.__name__, _ipv6_str)

        eq_(str(self.ip), ipv6_str)
        eq_(repr(self.ip), ipv6_str)
