# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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


import logging
import unittest

from nose.tools import eq_, raises

from ryu.lib.packet.bgp import (
    BGPFlowSpecTrafficRateCommunity,
    BGPFlowSpecTrafficActionCommunity,
    BGPFlowSpecRedirectCommunity,
    BGPFlowSpecTrafficMarkingCommunity,
    BGPFlowSpecVlanActionCommunity,
    BGPFlowSpecTPIDActionCommunity,
)

from ryu.services.protocols.bgp.core import BgpCoreError
from ryu.services.protocols.bgp.utils.bgp import create_v4flowspec_actions
from ryu.services.protocols.bgp.utils.bgp import create_v6flowspec_actions
from ryu.services.protocols.bgp.utils.bgp import create_l2vpnflowspec_actions


LOG = logging.getLogger(__name__)


class Test_Utils_BGP(unittest.TestCase):
    """
    Test case for ryu.services.protocols.bgp.utils.bgp
    """

    def _test_create_v4flowspec_actions(self, actions, expected_communities):
        communities = create_v4flowspec_actions(actions)
        expected_communities.sort(key=lambda x: x.subtype)
        communities.sort(key=lambda x: x.subtype)
        eq_(str(expected_communities), str(communities))

    def test_create_v4flowspec_actions_all_actions(self):
        actions = {
            'traffic_rate': {
                'as_number': 0,
                'rate_info': 100.0,
            },
            'traffic_action': {
                'action': 3,
            },
            'redirect': {
                'as_number': 10,
                'local_administrator': 10,
            },
            'traffic_marking': {
                'dscp': 24,
            }
        }
        expected_communities = [
            BGPFlowSpecTrafficRateCommunity(as_number=0, rate_info=100.0),
            BGPFlowSpecTrafficActionCommunity(action=3),
            BGPFlowSpecRedirectCommunity(as_number=10, local_administrator=10),
            BGPFlowSpecTrafficMarkingCommunity(dscp=24),
        ]
        self._test_create_v4flowspec_actions(actions, expected_communities)

    def test_create_v4flowspec_actions_without_actions(self):
        actions = None
        expected_communities = []
        self._test_create_v4flowspec_actions(actions, expected_communities)

    @raises(ValueError)
    def test_create_v4flowspec_actions_not_exist_actions(self):
        actions = {
            'traffic_test': {
                'test': 10,
            },
        }
        expected_communities = []
        self._test_create_v4flowspec_actions(actions, expected_communities)

    def _test_create_v6flowspec_actions(self, actions, expected_communities):
        communities = create_v6flowspec_actions(actions)
        expected_communities.sort(key=lambda x: x.subtype)
        communities.sort(key=lambda x: x.subtype)
        eq_(str(expected_communities), str(communities))

    def test_create_v6flowspec_actions_all_actions(self):
        actions = {
            'traffic_rate': {
                'as_number': 0,
                'rate_info': 100.0,
            },
            'traffic_action': {
                'action': 3,
            },
            'redirect': {
                'as_number': 10,
                'local_administrator': 10,
            },
            'traffic_marking': {
                'dscp': 24,
            }
        }
        expected_communities = [
            BGPFlowSpecTrafficRateCommunity(as_number=0, rate_info=100.0),
            BGPFlowSpecTrafficActionCommunity(action=3),
            BGPFlowSpecRedirectCommunity(as_number=10, local_administrator=10),
            BGPFlowSpecTrafficMarkingCommunity(dscp=24),
        ]
        self._test_create_v6flowspec_actions(actions, expected_communities)

    def test_create_v6flowspec_actions_without_actions(self):
        actions = None
        expected_communities = []
        self._test_create_v6flowspec_actions(actions, expected_communities)

    @raises(ValueError)
    def test_create_v6flowspec_actions_not_exist_actions(self):
        actions = {
            'traffic_test': {
                'test': 10,
            },
        }
        expected_communities = []
        self._test_create_v6flowspec_actions(actions, expected_communities)

    def _test_create_l2vpnflowspec_actions(self, actions, expected_communities):
        communities = create_l2vpnflowspec_actions(actions)
        expected_communities.sort(key=lambda x: x.subtype)
        communities.sort(key=lambda x: x.subtype)
        eq_(str(expected_communities), str(communities))

    def test_create_l2vpnflowspec_actions_all_actions(self):
        actions = {
            'traffic_rate': {
                'as_number': 0,
                'rate_info': 100.0,
            },
            'traffic_action': {
                'action': 3,
            },
            'redirect': {
                'as_number': 10,
                'local_administrator': 10,
            },
            'traffic_marking': {
                'dscp': 24,
            },
            'vlan_action': {
                'actions_1': (BGPFlowSpecVlanActionCommunity.POP |
                              BGPFlowSpecVlanActionCommunity.SWAP),
                'vlan_1': 3000,
                'cos_1': 3,
                'actions_2': BGPFlowSpecVlanActionCommunity.PUSH,
                'vlan_2': 4000,
                'cos_2': 2,
            },
            'tpid_action': {
                'actions': (BGPFlowSpecTPIDActionCommunity.TI |
                            BGPFlowSpecTPIDActionCommunity.TO),
                'tpid_1': 5,
                'tpid_2': 6,
            }
        }
        expected_communities = [
            BGPFlowSpecTrafficRateCommunity(as_number=0, rate_info=100.0),
            BGPFlowSpecTrafficActionCommunity(action=3),
            BGPFlowSpecRedirectCommunity(as_number=10, local_administrator=10),
            BGPFlowSpecTrafficMarkingCommunity(dscp=24),
            BGPFlowSpecVlanActionCommunity(
                actions_1=(BGPFlowSpecVlanActionCommunity.POP |
                           BGPFlowSpecVlanActionCommunity.SWAP),
                vlan_1=3000,
                cos_1=3,
                actions_2=BGPFlowSpecVlanActionCommunity.PUSH,
                vlan_2=4000,
                cos_2=2,
            ),
            BGPFlowSpecTPIDActionCommunity(
                actions=(BGPFlowSpecTPIDActionCommunity.TI |
                         BGPFlowSpecTPIDActionCommunity.TO),
                tpid_1=5,
                tpid_2=6,
            ),
        ]
        self._test_create_l2vpnflowspec_actions(actions, expected_communities)

    def test_create_l2vpnflowspec_actions_without_actions(self):
        actions = None
        expected_communities = []
        self._test_create_l2vpnflowspec_actions(actions, expected_communities)

    @raises(ValueError)
    def test_create_l2vpnflowspec_actions_not_exist_actions(self):
        actions = {
            'traffic_test': {
                'test': 10,
            },
        }
        expected_communities = []
        self._test_create_l2vpnflowspec_actions(actions, expected_communities)
