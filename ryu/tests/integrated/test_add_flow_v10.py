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

import logging

from ryu.tests.integrated import tester
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ether
from ryu.ofproto import nx_match

LOG = logging.getLogger(__name__)


class RunTest(tester.TestFlowBase):
    """ Test case for add flows of1.0
    """
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RunTest, self).__init__(*args, **kwargs)
        self._verify = []

    def add_action(self, dp, action):
        rule = nx_match.ClsRule()
        self.send_flow_mod(
            dp, rule, 0, dp.ofproto.OFPFC_ADD, 0, 0, None,
            0xffffffff, None, dp.ofproto.OFPFF_SEND_FLOW_REM, action)

    def add_rule(self, dp, rule):
        self.send_flow_mod(
            dp, rule, 0, dp.ofproto.OFPFC_ADD, 0, 0, None,
            0xffffffff, None, dp.ofproto.OFPFF_SEND_FLOW_REM, [])

    def send_flow_mod(self, dp, rule, cookie, command, idle_timeout,
                      hard_timeout, priority=None, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None):

        if priority is None:
            priority = dp.ofproto.OFP_DEFAULT_PRIORITY
        if out_port is None:
            out_port = dp.ofproto.OFPP_NONE

        match_tuple = rule.match_tuple()
        match = dp.ofproto_parser.OFPMatch(*match_tuple)

        m = dp.ofproto_parser.OFPFlowMod(
            dp, match, cookie, command, idle_timeout, hard_timeout,
            priority, buffer_id, out_port, flags, actions)

        dp.send_msg(m)

    def _verify_action(self, actions, type_, name, value):
        try:
            action = actions[0]
            if action.cls_action_type != type_:
                return "Action type error. send:%s, val:%s" \
                    % (type_, action.cls_action_type)
        except IndexError:
            return "Action is not setting."

        f_value = None
        if name:
            try:
                if isinstance(name, list):
                    f_value = [getattr(action, n) for n in name]
                else:
                    f_value = getattr(action, name)
            except AttributeError:
                pass

        if f_value != value:
            return "Value error. send:%s=%s val:%s" \
                % (name, value, f_value)
        return True

    def _verify_rule(self, rule, name, value):
        f_value = getattr(rule, name)
        if f_value != value:
            return "Value error. send:%s=%s val:%s" \
                % (name, value, f_value)
        return True

    def verify_default(self, dp, stats):
        verify = self._verify
        self._verify = []
        match = stats[0].match
        actions = stats[0].actions

        if len(verify) == 2:
            return self._verify_rule(match, *verify)
        elif len(verify) == 3:
            return self._verify_action(actions, *verify)
        else:
            return "self._verify is invalid."

    # Test of Actions
    def test_action_output(self, dp):
        out_port = 2
        self._verify = [dp.ofproto.OFPAT_OUTPUT,
                        'port', out_port]
        action = dp.ofproto_parser.OFPActionOutput(out_port)
        self.add_action(dp, [action, ])

    def test_rule_set_in_port(self, dp):
        in_port = 32
        self._verify = ['in_port', in_port]

        rule = nx_match.ClsRule()
        rule.set_in_port(in_port)
        self.add_rule(dp, rule)

    def test_action_vlan_vid(self, dp):
        vlan_vid = 2
        self._verify = [dp.ofproto.OFPAT_SET_VLAN_VID,
                        'vlan_vid', vlan_vid]
        action = dp.ofproto_parser.OFPActionVlanVid(vlan_vid)
        self.add_action(dp, [action, ])

    def test_action_vlan_pcp(self, dp):
        vlan_pcp = 4
        self._verify = [dp.ofproto.OFPAT_SET_VLAN_PCP,
                        'vlan_pcp', vlan_pcp]
        action = dp.ofproto_parser.OFPActionVlanPcp(vlan_pcp)
        self.add_action(dp, [action, ])

    def test_action_strip_vlan(self, dp):
        vlan_pcp = 4
        self._verify = [dp.ofproto.OFPAT_STRIP_VLAN,
                        None, None]
        action = dp.ofproto_parser.OFPActionStripVlan()
        self.add_action(dp, [action, ])

    def test_action_set_dl_src(self, dp):
        dl_src = '56:b3:42:04:b2:7a'
        dl_src_bin = self.haddr_to_bin(dl_src)
        self._verify = [dp.ofproto.OFPAT_SET_DL_SRC,
                        'dl_addr', dl_src_bin]
        action = dp.ofproto_parser.OFPActionSetDlSrc(dl_src_bin)
        self.add_action(dp, [action, ])

    def test_action_set_dl_dst(self, dp):
        dl_dst = 'c2:93:a2:fb:d0:f4'
        dl_dst_bin = self.haddr_to_bin(dl_dst)
        self._verify = [dp.ofproto.OFPAT_SET_DL_DST,
                        'dl_addr', dl_dst_bin]
        action = dp.ofproto_parser.OFPActionSetDlDst(dl_dst_bin)
        self.add_action(dp, [action, ])

    def test_action_set_nw_src(self, dp):
        nw_src = '216.132.81.105'
        nw_src_int = self.ipv4_to_int(nw_src)
        self._verify = [dp.ofproto.OFPAT_SET_NW_SRC,
                        'nw_addr', nw_src_int]
        action = dp.ofproto_parser.OFPActionSetNwSrc(nw_src_int)
        self.add_action(dp, [action, ])

    def test_action_set_nw_dst(self, dp):
        nw_dst = '223.201.206.3'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        self._verify = [dp.ofproto.OFPAT_SET_NW_DST,
                        'nw_addr', nw_dst_int]
        action = dp.ofproto_parser.OFPActionSetNwDst(nw_dst_int)
        self.add_action(dp, [action, ])

    def test_action_set_nw_tos(self, dp):
        # lowest two bits must be zero
        nw_tos = 1 << 2
        self._verify = [dp.ofproto.OFPAT_SET_NW_TOS,
                        'tos', nw_tos]
        action = dp.ofproto_parser.OFPActionSetNwTos(nw_tos)
        self.add_action(dp, [action, ])

    def test_action_set_tp_src(self, dp):
        tp_src = 55420
        self._verify = [dp.ofproto.OFPAT_SET_TP_SRC,
                        'tp', tp_src]
        action = dp.ofproto_parser.OFPActionSetTpSrc(tp_src)
        self.add_action(dp, [action, ])

    def test_action_set_tp_dst(self, dp):
        tp_dst = 15430
        self._verify = [dp.ofproto.OFPAT_SET_TP_DST,
                        'tp', tp_dst]
        action = dp.ofproto_parser.OFPActionSetTpDst(tp_dst)
        self.add_action(dp, [action, ])

    def test_action_enqueue(self, dp):
        port = 207
        queue_id = 4287508753
        self._verify = [dp.ofproto.OFPAT_ENQUEUE,
                        ['port', 'queue_id'], [port, queue_id]]
        action = dp.ofproto_parser.OFPActionEnqueue(port, queue_id)
        self.add_action(dp, [action, ])

    # Test of Rules
    def test_rule_set_in_port(self, dp):
        in_port = 32
        self._verify = ['in_port', in_port]

        rule = nx_match.ClsRule()
        rule.set_in_port(in_port)
        self.add_rule(dp, rule)

    def test_rule_set_dl_src(self, dp):
        dl_src = 'b8:a1:94:51:78:83'
        dl_src_bin = self.haddr_to_bin(dl_src)
        self._verify = ['dl_src', dl_src_bin]

        rule = nx_match.ClsRule()
        rule.set_dl_src(dl_src_bin)
        self.add_rule(dp, rule)

    def test_rule_set_dl_type_ip(self, dp):
        dl_type = ether.ETH_TYPE_IP
        self._verify = ['dl_type', dl_type]

        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)
        self.add_rule(dp, rule)

    def test_rule_set_dl_type_arp(self, dp):
        dl_type = ether.ETH_TYPE_ARP
        self._verify = ['dl_type', dl_type]

        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)
        self.add_rule(dp, rule)

    def test_rule_set_dl_type_vlan(self, dp):
        dl_type = ether.ETH_TYPE_8021Q
        self._verify = ['dl_type', dl_type]

        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)
        self.add_rule(dp, rule)

    def test_rule_set_dl_type_ipv6(self, dp):
        dl_type = ether.ETH_TYPE_IPV6
        self._verify = ['dl_type', dl_type]

        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)
        self.add_rule(dp, rule)

    def test_rule_set_dl_type_lacp(self, dp):
        dl_type = ether.ETH_TYPE_SLOW
        self._verify = ['dl_type', dl_type]

        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)
        self.add_rule(dp, rule)
