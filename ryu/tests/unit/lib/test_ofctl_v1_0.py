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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
from nose.tools import *

from ryu.lib import ofctl_v1_0
from ryu.ofproto import ofproto_v1_0, ofproto_v1_0_parser
from ryu.ofproto import ofproto_protocol

LOG = logging.getLogger('test_ofctl_v1_0')


class Test_ofctl_v1_0(unittest.TestCase):

    """ Test case for ofctl_v1_0
    """

    def setUp(self):
        self.dp = ofproto_protocol.ProtocolDesc(
            version=ofproto_v1_0.OFP_VERSION)
        self.attrs_list = [
            {"in_port": 3},
            {"dl_vlan": 3},
            {"dl_src": "11:11:11:11:11:11"},
            {"dl_dst": "11:11:11:11:11:12"},
            {"nw_tos": 16, "dl_type": 2048},
            {"nw_proto": 5, "dl_type": 2048},
            {"tp_src": 1, "nw_proto": 6, "dl_type": 2048},
            {"tp_dst": 2, "nw_proto": 6, "dl_type": 2048},
            {"nw_src": "192.168.1.5", "dl_type": 2048},
            {"nw_dst": "192.168.1.5/12", "dl_type": 2048},
            {"nw_dst": "192.168.1.5/1"},
            {"nw_dst": "192.168.1.5/12"},
            {"dl_vlan_pcp": 3}
        ]

    def tearDown(self):
        pass

    def test_match_to_str(self):
        for attrs in self.attrs_list:
            match = ofctl_v1_0.to_match(self.dp, attrs)
            str = ofctl_v1_0.match_to_str(match)
            eq_(attrs, str)
