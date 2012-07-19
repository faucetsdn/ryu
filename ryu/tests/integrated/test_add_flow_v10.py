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

from ryu.controller import handler
from ryu.controller.handler import set_ev_cls
from ryu.tests.integrated import tester
from ryu.ofproto import nx_match

LOG = logging.getLogger(__name__)

_target = 'br-tester'


class RunTest(tester.RunTestBase):

    def __init__(self):
        super(RunTest, self).__init__()

    def send_flow_mod(self, rule, cookie, command, idle_timeout, hard_timeout,
                      priority=None, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None):

        if priority is None:
            priority = self.ofproto.OFP_DEFAULT_PRIORITY
        if out_port is None:
            out_port = self.ofproto.OFPP_NONE

        match_tuple = rule.match_tuple()
        match = self.ofproto_parser.OFPMatch(*match_tuple)
        flow_mod = self.ofproto_parser.OFPFlowMod(
            self.datapath, match, cookie, command, idle_timeout, hard_timeout,
            priority, buffer_id, out_port, flags, actions)

        self.datapath.send_msg(flow_mod)

    def test_action_output(self):
        datapath = self.datapath
        ofproto = self.ofproto

        out_port = 2
        self.set_val('out_port', out_port)

        actions = [
            datapath.ofproto_parser.OFPActionOutput(out_port),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_output(self):
        ovs_actions = {}
        out_port = self.get_val('out_port')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_out_port = ovs_actions['output']
        except (KeyError, IndexError):
            ovs_out_port = ''

        if ovs_out_port == '' or int(ovs_out_port) != out_port:
            err = 'send_actions=[output:%s] ovs_actions=[%s]' \
                  % (out_port, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_vlan_vid(self):
        datapath = self.datapath
        ofproto = self.ofproto

        vlan_vid = 3
        self.set_val('vlan_vid', vlan_vid)

        actions = [
            datapath.ofproto_parser.OFPActionVlanVid(vlan_vid),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_vlan_vid(self):
        ovs_actions = {}
        vlan_vid = self.get_val('vlan_vid')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_vlan_vid = ovs_actions['mod_vlan_vid']
        except (KeyError, IndexError):
            ovs_vlan_vid = ''

        if ovs_vlan_vid == '' or int(ovs_vlan_vid) != vlan_vid:
            err = 'send_actions=[vlan_vid:%s] ovs_actions=[%s]' \
                  % (vlan_vid, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_vlan_pcp(self):
        datapath = self.datapath
        ofproto = self.ofproto

        vlan_pcp = 4
        self.set_val('vlan_pcp', vlan_pcp)

        actions = [
            datapath.ofproto_parser.OFPActionVlanPcp(vlan_pcp),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_vlan_pcp(self):
        ovs_actions = {}
        vlan_pcp = self.get_val('vlan_pcp')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_vlan_pcp = ovs_actions['mod_vlan_pcp']
        except (KeyError, IndexError):
            ovs_vlan_pcp = ''

        if ovs_vlan_pcp == '' or int(ovs_vlan_pcp) != vlan_pcp:
            err = 'send_actions=[vlan_vid:%s] ovs_actions=[%s]' \
                  % (vlan_pcp, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_strip_vlan(self):
        datapath = self.datapath
        ofproto = self.ofproto

        actions = [
            datapath.ofproto_parser.OFPActionStripVlan(),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_strip_vlan(self):
        ovs_actions = {}
        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
        except (KeyError, IndexError):
            pass

        if not 'strip_vlan' in ovs_actions:
            err = 'send_actions=[strip_vlan] ovs_actions=[%s]' \
                  % (self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_set_dl_src(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_src = '56:b3:42:04:b2:7a'
        self.set_val('dl_src', dl_src)

        dl_src_bin = self.haddr_to_bin(dl_src)
        actions = [
            datapath.ofproto_parser.OFPActionSetDlSrc(dl_src_bin),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_set_dl_src(self):
        ovs_actions = {}
        dl_src = self.get_val('dl_src')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_dl_src = ovs_actions['mod_dl_src']
        except (KeyError, IndexError):
            ovs_dl_src = ''

        if ovs_dl_src == '' or ovs_dl_src != dl_src:
            err = 'send_actions=[dl_src:%s] ovs_actions=[%s]' \
                  % (dl_src, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_set_dl_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_dst = 'c2:93:a2:fb:d0:f4'
        self.set_val('dl_dst', dl_dst)

        dl_dst_bin = self.haddr_to_bin(dl_dst)
        actions = [
            datapath.ofproto_parser.OFPActionSetDlDst(dl_dst_bin),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_set_dl_dst(self):
        ovs_actions = {}
        dl_dst = self.get_val('dl_dst')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_dl_dst = ovs_actions['mod_dl_dst']
        except (KeyError, IndexError):
            ovs_dl_dst = ''

        if ovs_dl_dst == '' or ovs_dl_dst != dl_dst:
            err = 'send_actions=[dl_dst:%s] ovs_actions=[%s]' \
                  % (dl_dst, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_set_nw_src(self):
        datapath = self.datapath
        ofproto = self.ofproto

        nw_src = '216.132.81.105'
        self.set_val('nw_src', nw_src)

        nw_src_int = self.ipv4_to_int(nw_src)

        actions = [
            datapath.ofproto_parser.OFPActionSetNwSrc(nw_src_int),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_set_nw_src(self):
        ovs_actions = {}
        nw_src = self.get_val('nw_src')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_nw_src = ovs_actions['mod_nw_src']
        except (KeyError, IndexError):
            ovs_nw_src = ''

        if ovs_nw_src == '' or ovs_nw_src != nw_src:
            err = 'send_actions=[nw_src:%s] ovs_actions=[%s]' \
                  % (nw_src, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_set_nw_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto

        nw_dst = '223.201.206.3'
        self.set_val('nw_dst', nw_dst)

        nw_dst_int = self.ipv4_to_int(nw_dst)

        actions = [
            datapath.ofproto_parser.OFPActionSetNwDst(nw_dst_int),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_set_nw_dst(self):
        ovs_actions = {}
        nw_dst = self.get_val('nw_dst')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_nw_dst = ovs_actions['mod_nw_dst']
        except (KeyError, IndexError):
            ovs_nw_dst = ''

        if ovs_nw_dst == '' or ovs_nw_dst != nw_dst:
            err = 'send_actions=[nw_dst:%s] ovs_actions=[%s]' \
                  % (nw_dst, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_set_nw_tos(self):
        datapath = self.datapath
        ofproto = self.ofproto

        nw_tos = 111
        self.set_val('nw_tos', nw_tos)

        actions = [
            datapath.ofproto_parser.OFPActionSetNwTos(nw_tos),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_set_nw_tos(self):
        ovs_actions = {}
        nw_tos = self.get_val('nw_tos')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_nw_tos = ovs_actions['mod_nw_tos']
        except (KeyError, IndexError):
            ovs_nw_tos = ''

        if ovs_nw_tos == '' or int(ovs_nw_tos) != nw_tos:
            err = 'send_actions=[nw_tos:%s] ovs_actions=[%s]' \
                  % (nw_tos, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_set_tp_src(self):
        datapath = self.datapath
        ofproto = self.ofproto

        tp_src = 55420
        self.set_val('tp_src', tp_src)

        actions = [
            datapath.ofproto_parser.OFPActionSetTpSrc(tp_src),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_set_tp_src(self):
        ovs_actions = {}
        tp_src = self.get_val('tp_src')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_tp_src = ovs_actions['mod_tp_src']
        except (KeyError, IndexError):
            ovs_tp_src = ''

        if ovs_tp_src == '' or int(ovs_tp_src) != tp_src:
            err = 'send_actions=[tp_src:%s] ovs_actions=[%s]' \
                  % (tp_src, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_set_tp_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto

        tp_dst = 15430
        self.set_val('tp_dst', tp_dst)

        actions = [
            datapath.ofproto_parser.OFPActionSetTpDst(tp_dst),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_set_tp_dst(self):
        ovs_actions = {}
        tp_dst = self.get_val('tp_dst')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_tp_dst = ovs_actions['mod_tp_dst']
        except (KeyError, IndexError):
            ovs_tp_dst = ''

        if ovs_tp_dst == '' or int(ovs_tp_dst) != tp_dst:
            err = 'send_actions=[tp_src:%s] ovs_actions=[%s]' \
                  % (tp_dst, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_action_enqueue(self):
        datapath = self.datapath
        ofproto = self.ofproto

        port = 207
        queue_id = 4287508753
        self.set_val('enqueue', str(port) + 'q' + str(queue_id))

        actions = [
            datapath.ofproto_parser.OFPActionEnqueue(port, queue_id),
        ]

        rule = nx_match.ClsRule()
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_action_enqueue(self):
        ovs_actions = {}
        enqueue = self.get_val('enqueue')

        try:
            ovs_actions = self.get_ovs_flows(_target)[0]['actions']
            ovs_enqueue = ovs_actions['enqueue']
        except (KeyError, IndexError):
            ovs_enqueue = ''

        if ovs_enqueue == '' or ovs_enqueue != enqueue:
            err = 'send_actions=[enqueue:%s] ovs_actions=[%s]' \
                  % (enqueue, self.cnv_txt(ovs_actions))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_rule_set_in_port(self):
        datapath = self.datapath
        ofproto = self.ofproto

        in_port = 32
        self.set_val('in_port', in_port)

        actions = []
        rule = nx_match.ClsRule()
        rule.set_in_port(in_port)
        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_rule_set_in_port(self):
        ovs_rules = {}
        in_port = self.get_val('in_port')

        try:
            ovs_rules = self.get_ovs_flows(_target)[0]['rules']
            ovs_in_port = ovs_rules['in_port']
        except (KeyError, IndexError):
            ovs_in_port = ''

        if ovs_in_port == '' or int(ovs_in_port) != in_port:
            err = 'send_rules=[in_port:%s] ovs_rules=[%s]' \
                  % (in_port, self.cnv_txt(ovs_rules))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_rule_set_dl_src(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_src = 'b8:a1:94:51:78:83'
        self.set_val('dl_src', dl_src)

        dl_src_bin = self.haddr_to_bin(dl_src)

        actions = []
        rule = nx_match.ClsRule()
        rule.set_dl_src(dl_src_bin)

        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_rule_set_dl_src(self):
        ovs_rules = {}
        dl_src = self.get_val('dl_src')

        try:
            ovs_rules = self.get_ovs_flows(_target)[0]['rules']
            ovs_dl_src = ovs_rules['dl_src']
        except (KeyError, IndexError):
            ovs_dl_src = ''

        if ovs_dl_src == '' or ovs_dl_src != dl_src:
            err = 'send_rules=[dl_src:%s] ovs_rules=[%s]' \
                  % (dl_src, self.cnv_txt(ovs_rules))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_rule_set_dl_type_ip(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_type = nx_match.ETH_TYPE_IP
        self.set_val('dl_type', 'ip')

        actions = []
        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)

        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_rule_set_dl_type_ip(self):
        ovs_rules = {}
        dl_type = self.get_val('dl_type')

        try:
            ovs_rules = self.get_ovs_flows(_target)[0]['rules']
        except (KeyError, IndexError):
            pass

        if not dl_type in ovs_rules:
            err = 'send_rules=[dl_type:%s] ovs_rules=[%s]' \
                  % (dl_type, self.cnv_txt(ovs_rules))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_rule_set_dl_type_arp(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_type = nx_match.ETH_TYPE_ARP
        self.set_val('dl_type', 'arp')

        actions = []
        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)

        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_rule_set_dl_type_arp(self):
        ovs_rules = {}
        dl_type = self.get_val('dl_type')

        try:
            ovs_rules = self.get_ovs_flows(_target)[0]['rules']
        except (KeyError, IndexError):
            pass

        if not dl_type in ovs_rules:
            err = 'send_rules=[dl_type:%s] ovs_rules=[%s]' \
                  % (dl_type, self.cnv_txt(ovs_rules))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_rule_set_dl_type_vlan(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_type = nx_match.ETH_TYPE_VLAN
        self.set_val('dl_type', nx_match.ETH_TYPE_VLAN)

        actions = []
        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)

        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_rule_set_dl_type_vlan(self):
        ovs_rules = {}
        dl_type = self.get_val('dl_type')

        try:
            ovs_rules = self.get_ovs_flows(_target)[0]['rules']
            ovs_dl_type = ovs_rules['dl_type']
        except (KeyError, IndexError):
            ovs_dl_type = ''

        if ovs_dl_type == '' or int(ovs_dl_type, 16) != dl_type:
            err = 'send_rules=[dl_src:%s] ovs_rules=[%s]' \
                  % (dl_type, self.cnv_txt(ovs_rules))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_rule_set_dl_type_ipv6(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_type = nx_match.ETH_TYPE_IPV6
        self.set_val('dl_type', 'ipv6')

        actions = []
        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)

        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_rule_set_dl_type_ipv6(self):
        ovs_rules = {}
        dl_type = self.get_val('dl_type')

        try:
            ovs_rules = self.get_ovs_flows(_target)[0]['rules']
        except (KeyError, IndexError):
            pass

        if not dl_type in ovs_rules:
            err = 'send_rules=[dl_type:%s] ovs_rules=[%s]' \
                  % (dl_type, self.cnv_txt(ovs_rules))
            self.results(ret=False, msg=err)
            return
        self.results()

    def test_rule_set_dl_type_lacp(self):
        datapath = self.datapath
        ofproto = self.ofproto

        dl_type = nx_match.ETH_TYPE_LACP
        self.set_val('dl_type', nx_match.ETH_TYPE_LACP)

        actions = []
        rule = nx_match.ClsRule()
        rule.set_dl_type(dl_type)

        self.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    def check_rule_set_dl_type_lacp(self):
        ovs_rules = {}
        dl_type = self.get_val('dl_type')

        try:
            ovs_rules = self.get_ovs_flows(_target)[0]['rules']
            ovs_dl_type = ovs_rules['dl_type']
        except (KeyError, IndexError):
            ovs_dl_type = ''

        if ovs_dl_type == '' or int(ovs_dl_type, 16) != dl_type:
            err = 'send_rules=[dl_src:%s] ovs_rules=[%s]' \
                  % (dl_type, self.cnv_txt(ovs_rules))
            self.results(ret=False, msg=err)
            return
        self.results()
