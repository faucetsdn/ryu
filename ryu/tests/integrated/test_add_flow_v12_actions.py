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

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_AH = 51
IPPROTO_ICMPV6 = 58
IPPROTO_NONE = 59
IPPROTO_DSTOPTS = 60
IPPROTO_SCTP = 132

ETH_TYPE_MPLS = 0x8847


class RunTest(tester.RunTestBase):
    """ Test case for add flows of Actions
    """

    def __init__(self):
        super(RunTest, self).__init__()

    def _set_val(self, type_, name, val):
        self.set_val('type', type_)
        self.set_val('name', name)
        self.set_val('val', val)

    def _get_val(self):
        type_ = self.get_val('type')
        name = self.get_val('name')
        val = self.get_val('val')
        return (type_, name, val)

    def _check_default(self):
        type_, name, val = self._get_val()

        ovs_flow = {}
        try:
            ovs_flow = self.get_ovs_flows(_target)[0][type_]
        except (KeyError, IndexError):
            pass

        ng = 0
        if val == None:
            if name in ovs_flow:
                ng = 1
        elif not name in ovs_flow or val != ovs_flow[name]:
            ng = 1

        if ng:
            err = ' send (%s:%s=%s)\n flow (%s:%s)' \
                   % (type_, name, val, type_, self.cnv_txt(ovs_flow))
            self.results(ret=False, msg=err)
        else:
            self.results()

    # Test of General Actions
    def test_action_output(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        out_port = 255
        self._set_val('apply_actions',
                      'output',
                      str(out_port))

        match = ofproto_parser.OFPMatch()
        actions = [
                   ofproto_parser.OFPActionOutput(out_port, 0),
                  ]
        inst = [
                ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions),
               ]

        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_drop(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        self._set_val('apply_actions',
                      'drop',
                      'drop')

        match = ofproto_parser.OFPMatch()
        inst = [
               ]

        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    # Test of Push-Tag/Pop-Tag Actions
    def test_action_push_vlan(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        push_vlan = nx_match.ETH_TYPE_VLAN
        self._set_val('apply_actions',
                      'push_vlan',
                      hex(push_vlan))

        match = ofproto_parser.OFPMatch()
        actions = [
                   ofproto_parser.OFPActionPushVlan(push_vlan),
                  ]
        inst = [
                ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions),
               ]

        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_pop_vlan(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        self._set_val('apply_actions',
                      'pop_vlan',
                      'pop_vlan')

        match = ofproto_parser.OFPMatch()
        actions = [
                   ofproto_parser.OFPActionPopVlan(),
                  ]
        inst = [
                ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions),
               ]

        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_push_mpls(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        push_mpls = ETH_TYPE_MPLS
        self._set_val('apply_actions',
                      'push_mpls',
                      hex(push_mpls))

        match = ofproto_parser.OFPMatch()
        actions = [
                   ofproto_parser.OFPActionPushMpls(push_mpls),
                  ]
        inst = [
                ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions),
               ]

        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_pop_mpls(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        pop_mpls = nx_match.ETH_TYPE_IP
        self._set_val('apply_actions',
                      'pop_mpls',
                      hex(pop_mpls))

        match = ofproto_parser.OFPMatch()
        actions = [
                   ofproto_parser.OFPActionPopMpls(pop_mpls),
                  ]
        inst = [
                ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions),
               ]

        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    # Test of Set-Filed Actions
    def test_action_set_field_dl_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_dst = 'e2:7a:09:79:0b:0f'
        self._set_val('apply_actions',
                      'set_field',
                      dl_dst + '->eth_dst')

        dl_dst_bin = self.haddr_to_bin(dl_dst)

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_ETH_DST, dl_dst_bin)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_dl_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_src = '08:82:63:b6:62:05'
        self._set_val('apply_actions',
                      'set_field',
                      dl_src + '->eth_src')
        dl_src_bin = self.haddr_to_bin(dl_src)

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_ETH_SRC, dl_src_bin)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_dl_type(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_type = nx_match.ETH_TYPE_IPV6
        self._set_val('apply_actions',
                      'set_field',
                      hex(dl_type) + '->eth_type')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_ETH_TYPE, dl_type)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_vlan_vid(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        dl_vlan = 0x1e4
        self._set_val('apply_actions',
                      'set_field',
                      str(dl_vlan) + '->dl_vlan')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_VLAN_VID, dl_vlan)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_vlan_pcp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        vlan_pcp = 3
        self._set_val('apply_actions',
                      'set_field',
                      str(vlan_pcp) + '->dl_vlan_pcp')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_VLAN_PCP, vlan_pcp)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_nw_dscp(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        nw_dscp = 32
        self._set_val('apply_actions',
                      'set_field',
                      str(nw_dscp) + '->nw_tos')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_IP_DSCP, nw_dscp)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_nw_ecn(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        nw_ecn = 1
        self._set_val('apply_actions',
                      'set_field',
                      str(nw_ecn) + '->nw_ecn')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_IP_ECN, nw_ecn)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ip_proto(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        ip_proto = IPPROTO_TCP
        self._set_val('apply_actions',
                      'set_field',
                      str(ip_proto) + '->nw_proto')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_IP_PROTO, ip_proto)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv4_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        ipv4_src = '192.168.3.92'
        self._set_val('apply_actions',
                      'set_field',
                      ipv4_src + '->ip_src')
        ipv4_src_int = self.ipv4_to_int(ipv4_src)

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_IPV4_SRC, ipv4_src_int)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv4_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        ipv4_dst = '192.168.74.122'
        self._set_val('apply_actions',
                      'set_field',
                      ipv4_dst + '->ip_dst')
        ipv4_dst_int = self.ipv4_to_int(ipv4_dst)

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_IPV4_DST, ipv4_dst_int)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_tcp_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        tcp_src = 105
        self._set_val('apply_actions',
                      'set_field',
                      str(tcp_src) + '->tcp_src')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_TCP_SRC, tcp_src)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_tcp_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        tcp_dst = 75
        self._set_val('apply_actions',
                      'set_field',
                      str(tcp_dst) + '->tcp_dst')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_TCP_DST, tcp_dst)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_udp_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        udp_src = 197
        self._set_val('apply_actions',
                      'set_field',
                      str(udp_src) + '->udp_src')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_UDP_SRC, udp_src)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_udp_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        udp_dst = 17
        self._set_val('apply_actions',
                      'set_field',
                      str(udp_dst) + '->udp_dst')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_UDP_DST, udp_dst)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_icmpv4_type(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        icmp_type = 8
        self._set_val('apply_actions',
                      'set_field',
                      str(icmp_type) + '->icmp_type')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_ICMPV4_TYPE, icmp_type)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_icmpv4_code(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        icmp_code = 2
        self._set_val('apply_actions',
                      'set_field',
                      str(icmp_code) + '->icmp_code')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_ICMPV4_CODE, icmp_code)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_arp_op(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        arp_op = 2
        self._set_val('apply_actions',
                      'set_field',
                      str(arp_op) + '->arp_op')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_ARP_OP, arp_op)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_arp_spa(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        nw_src = '192.168.132.179'
        nw_src_int = self.ipv4_to_int(nw_src)
        self._set_val('apply_actions',
                      'set_field',
                      str(nw_src) + '->arp_spa')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_ARP_SPA, nw_src_int)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_arp_tpa(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        nw_dst = '192.168.118.85'
        nw_dst_int = self.ipv4_to_int(nw_dst)
        self._set_val('apply_actions',
                      'set_field',
                      str(nw_dst) + '->arp_tpa')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_ARP_TPA, nw_dst_int)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_arp_sha(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        arp_sha = '50:29:e7:7f:6c:7f'
        arp_sha_bin = self.haddr_to_bin(arp_sha)
        self._set_val('apply_actions',
                      'set_field',
                      arp_sha + '->arp_sha')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_ARP_SHA, arp_sha_bin)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_arp_tha(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        arp_tha = '71:c8:72:2f:47:fd'
        arp_tha_bin = self.haddr_to_bin(arp_tha)
        self._set_val('apply_actions',
                      'set_field',
                      arp_tha + '->arp_tha')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_ARP_THA, arp_tha_bin)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv6_src(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        ipv6_src = '7527:c798:c772:4a18:117a:14ff:c1b6:e4ef'
        ipv6_src_int = self.ipv6_to_int(ipv6_src)
        self._set_val('apply_actions',
                      'set_field',
                      ipv6_src + '->ipv6_src')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_IPV6_SRC, ipv6_src_int)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv6_dst(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        ipv6_dst = '8893:65b3:6b49:3bdb:3d2:9401:866c:c96'
        ipv6_dst_int = self.ipv6_to_int(ipv6_dst)
        self._set_val('apply_actions',
                      'set_field',
                      ipv6_dst + '->ipv6_dst')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_IPV6_DST, ipv6_dst_int)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv6_flabel(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        flabel = 0x2c12
        self._set_val('apply_actions',
                      'set_field',
                      hex(flabel) + '->ipv6_label')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_IPV6_FLABEL, flabel)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_icmpv6_type(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        icmp_type = 129
        self._set_val('apply_actions',
                      'set_field',
                      str(icmp_type) + '->icmpv6_type')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_ICMPV6_TYPE, icmp_type)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_icmpv6_code(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        icmp_code = 129
        self._set_val('apply_actions',
                      'set_field',
                      str(icmp_code) + '->icmpv6_code')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_ICMPV6_CODE, icmp_code)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv6_nd_target(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        target = "5420:db3f:921b:3e33:2791:98f:dd7f:2e19"
        target_int = self.ipv6_to_int(target)
        self._set_val('apply_actions',
                      'set_field',
                      target + '->nd_target')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_IPV6_ND_TARGET, target_int)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv6_nd_sll(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        sll = "54:db:3f:3e:27:19"
        sll_bin = self.haddr_to_bin(sll)
        self._set_val('apply_actions',
                      'set_field',
                      sll + '->nd_sll')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_IPV6_ND_SLL, sll_bin)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_ipv6_nd_tll(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        tll = "83:13:48:1e:d0:b0"
        tll_bin = self.haddr_to_bin(tll)
        self._set_val('apply_actions',
                      'set_field',
                      tll + '->nd_tll')

        f1 = ofproto_parser.OFPMatchField.make(
                 ofproto.OXM_OF_IPV6_ND_TLL, tll_bin)
        actions = [
                   ofproto_parser.OFPActionSetField(f1),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_mpls_label(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        label = 0x4cd41
        self._set_val('apply_actions',
                      'set_field',
                      str(label) + '->mpls_label')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_MPLS_LABEL, label)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_set_field_mpls_tc(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        tc = 0b101
        self._set_val('apply_actions',
                      'set_field',
                      str(tc) + '->mpls_tc')

        field = ofproto_parser.OFPMatchField.make(
                     ofproto.OXM_OF_MPLS_TC, tc)
        actions = [
                   ofproto_parser.OFPActionSetField(field),
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    # Test of Change-TTL Actions
    def test_action_set_mpls_ttl(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        mpls_ttl = 8
        self._set_val('apply_actions',
                      'set_mpls_ttl',
                      str(mpls_ttl))

        actions = [
                   ofproto_parser.OFPActionSetMplsTtl(mpls_ttl)
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_dec_mpls_ttl(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        self._set_val('apply_actions',
                      'dec_mpls_ttl',
                      'dec_mpls_ttl')
        actions = [
                   ofproto_parser.OFPActionDecMplsTtl()
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_copy_ttl_out(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        self._set_val('apply_actions',
                      'copy_ttl_out',
                      'copy_ttl_out')
        actions = [
                   ofproto_parser.OFPActionCopyTtlOut()
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)

    def test_action_copy_ttl_in(self):
        datapath = self.datapath
        ofproto = self.ofproto
        ofproto_parser = self.ofproto_parser

        self._set_val('apply_actions',
                      'copy_ttl_in',
                      'copy_ttl_in')
        actions = [
                   ofproto_parser.OFPActionCopyTtlIn()
                  ]
        inst = [ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        match = ofproto_parser.OFPMatch()
        m = ofproto_parser.OFPFlowMod(
                datapath, 0, 0, 0, ofproto.OFPFC_ADD, 0, 0, 0, 0xffffffff,
                ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)
        datapath.send_msg(m)
