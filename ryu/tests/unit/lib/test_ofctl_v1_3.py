# Copyright (C) 2013 Stratosphere Inc.
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
from nose.tools import *

from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto.ofproto_v1_3_parser import OFPActionPopMpls

LOG = logging.getLogger('test_ofctl_v1_3')


class Test_ofctl_v1_3(unittest.TestCase):

    """ Test case for ofctl_v1_3
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_to_actions_pop_mpls(self):
        dp = ofproto_protocol.ProtocolDesc(version=ofproto_v1_3.OFP_VERSION)

        acts = [
            {
                'type': 'POP_MPLS',
                'ethertype': 0x0800
            }
        ]
        result = ofctl_v1_3.to_actions(dp, acts)
        insts = result[0]
        act = insts.actions[0]
        ok_(isinstance(act, OFPActionPopMpls))
        eq_(act.ethertype, 0x0800)
