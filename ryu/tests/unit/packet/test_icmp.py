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
import inspect
import logging

from nose.tools import *
from nose.plugins.skip import Skip, SkipTest
from ryu.lib.packet import icmp


LOG = logging.getLogger(__name__)


class Test_icmp_dest_unreach(unittest.TestCase):

    type_ = icmp.ICMP_DEST_UNREACH
    code = icmp.ICMP_HOST_UNREACH_CODE
    csum = 0

    mtu = 10
    data = 'abc'
    data_len = len(data)
    dst_unreach = icmp.dest_unreach(data_len=data_len, mtu=mtu, data=data)

    ic = icmp.icmp(type_, code, csum, data=dst_unreach)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_to_string(self):
        data_values = {'data': self.data,
                       'data_len': self.data_len,
                       'mtu': self.mtu}
        _data_str = ','.join(['%s=%s' % (k, repr(data_values[k]))
                              for k, v in inspect.getmembers(self.dst_unreach)
                              if k in data_values])
        data_str = '%s(%s)' % (icmp.dest_unreach.__name__, _data_str)

        icmp_values = {'type': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': data_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(self.ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmp.icmp.__name__, _ic_str)

        eq_(str(self.ic), ic_str)
        eq_(repr(self.ic), ic_str)
