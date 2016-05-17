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
from ryu.ofproto.ofproto_common import *


LOG = logging.getLogger('test_ofproto_common')


class TestOfprotCommon(unittest.TestCase):
    """ Test case for ofproto_common
    """

    def test_struct_ofp_header(self):
        eq_(OFP_HEADER_PACK_STR, '!BBHI')
        eq_(OFP_HEADER_SIZE, 8)

    def test_define_constants(self):
        eq_(OFP_TCP_PORT, 6653)
        eq_(OFP_SSL_PORT, 6653)
