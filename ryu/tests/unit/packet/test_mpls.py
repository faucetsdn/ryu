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
from ryu.lib.packet import mpls


LOG = logging.getLogger(__name__)


class Test_mpls(unittest.TestCase):

    label = 29
    exp = 6
    bsb = 1
    ttl = 64
    mp = mpls.mpls(label, exp, bsb, ttl)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_to_string(self):
        mpls_values = {'label': self.label,
                       'exp': self.exp,
                       'bsb': self.bsb,
                       'ttl': self.ttl}
        _mpls_str = ','.join(['%s=%s' % (k, repr(mpls_values[k]))
                              for k, v in inspect.getmembers(self.mp)
                              if k in mpls_values])
        mpls_str = '%s(%s)' % (mpls.mpls.__name__, _mpls_str)

        eq_(str(self.mp), mpls_str)
        eq_(repr(self.mp), mpls_str)
