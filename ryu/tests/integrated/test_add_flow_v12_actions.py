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

from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.tests.integrated import tester

LOG = logging.getLogger(__name__)


class RunTest(tester.TestFlowBase):
    """ Test case for add flows of Actions
    """
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RunTest, self).__init__(*args, **kwargs)

        self._verify = []

    def add_apply_actions(self, dp, actions, match=None):
        inst = [dp.ofproto_parser.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if match is None:
            match = dp.ofproto_parser.OFPMatch()
        m = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, 0,
                                         dp.ofproto.OFPFC_ADD,
                                         0, 0, 0xff, 0xffffffff,
                                         dp.ofproto.OFPP_ANY,
                                         dp.ofproto.OFPG_ANY,
                                         0, match, inst)
        dp.send_msg(m)

    def add_set_field_action(self, dp, field, value, match=None):
        self._verify = [dp.ofproto.OFPAT_SET_FIELD,
                        'field', field, value]
        f = dp.ofproto_parser.OFPMatchField.make(field, value)
        actions = [dp.ofproto_parser.OFPActionSetField(f), ]
        self.add_apply_actions(dp, actions, match=match)

    def verify_default(self, dp, stats):
        verify = self._verify
        self._verify = []

        type_ = name = field = value = None
        if len(verify) == 1:
            (type_, ) = verify
        elif len(verify) == 3:
            (type_, name, value) = verify
        elif len(verify) == 4:
            (type_, name, field, value) = verify
        else:
            return "self._verify is invalid."

        try:
            action = stats[0].instructions[0].actions[0]
            if action.cls_action_type != type_:
                return "Action type error. send:%s, val:%s" \
                    % (type_, action.cls_action_type)
        except IndexError:
            return "Action is not setting."

        s_val = None
        if name:
            try:
                s_val = getattr(action, name)
            except AttributeError:
                pass

        if name == 'field':
            if s_val.header != field:
                return "Field error. send:%s val:%s" \
                    % (field, s_val.field)
            s_val = s_val.value

        if name and s_val != value:
                return "Value error. send:%s=%s val:%s" \
                    % (name, value, s_val)

        return True

    def verify_action_drop(self, dp, stats):
        for s in stats:
            for i in s.instructions:
                if len(i.actions):
                    return "has actions. %s" % (i.actions)
        return True

    # Test of General Actions
    def test_action_output(self, dp):
        out_port = 255
        self._verify = [dp.ofproto.OFPAT_OUTPUT,
                        'port', out_port]

        actions = [dp.ofproto_parser.OFPActionOutput(out_port, 0), ]
        self.add_apply_actions(dp, actions)

    def test_action_drop(self, dp):
        self.add_apply_actions(dp, [])

    # Test of Push-Tag/Pop-Tag Actions
    def test_action_push_vlan(self, dp):
        ethertype = ether.ETH_TYPE_8021Q
        self._verify = [dp.ofproto.OFPAT_PUSH_VLAN,
                        'ethertype', ethertype]

        actions = [dp.ofproto_parser.OFPActionPushVlan(ethertype)]
        self.add_apply_actions(dp, actions)

    def test_action_pop_vlan(self, dp):
        self._verify = [dp.ofproto.OFPAT_POP_VLAN, ]

        actions = [dp.ofproto_parser.OFPActionPopVlan(), ]
        self.add_apply_actions(dp, actions)

    def test_action_push_mpls(self, dp):
        ethertype = ether.ETH_TYPE_MPLS
        self._verify = [dp.ofproto.OFPAT_PUSH_MPLS,
                        'ethertype', ethertype]

        actions = [dp.ofproto_parser.OFPActionPushMpls(ethertype), ]
        self.add_apply_actions(dp, actions)

    def test_action_pop_mpls(self, dp):
        ethertype = ether.ETH_TYPE_8021Q
        self._verify = [dp.ofproto.OFPAT_POP_MPLS,
                        'ethertype', ethertype]
        actions = [dp.ofproto_parser.OFPActionPopMpls(ethertype), ]
        self.add_apply_actions(dp, actions)

    # Test of Set-Filed Actions
    def test_action_set_field_dl_dst(self, dp):
        field = dp.ofproto.OXM_OF_ETH_DST
        dl_dst = 'e2:7a:09:79:0b:0f'
        value = self.haddr_to_bin(dl_dst)

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_dl_src(self, dp):
        field = dp.ofproto.OXM_OF_ETH_SRC
        dl_src = '08:82:63:b6:62:05'
        value = self.haddr_to_bin(dl_src)

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_dl_type(self, dp):
        field = dp.ofproto.OXM_OF_ETH_TYPE
        value = ether.ETH_TYPE_IPV6

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_vlan_vid(self, dp):
        field = dp.ofproto.OXM_OF_VLAN_VID
        value = 0x1e4

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_vlan_pcp(self, dp):
        field = dp.ofproto.OXM_OF_VLAN_PCP
        value = 3

        match = dp.ofproto_parser.OFPMatch()
        match.set_vlan_vid(1)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_nw_dscp(self, dp):
        field = dp.ofproto.OXM_OF_IP_DSCP
        value = 32

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_nw_ecn(self, dp):
        field = dp.ofproto.OXM_OF_IP_ECN
        value = 1

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_ip_proto(self, dp):
        field = dp.ofproto.OXM_OF_IP_PROTO
        value = inet.IPPROTO_TCP

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_ipv4_src(self, dp):
        field = dp.ofproto.OXM_OF_IPV4_SRC
        ipv4_src = '192.168.3.92'
        value = self.ipv4_to_int(ipv4_src)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_ipv4_dst(self, dp):
        field = dp.ofproto.OXM_OF_IPV4_DST
        ipv4_dst = '192.168.74.122'
        value = self.ipv4_to_int(ipv4_dst)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_tcp_src(self, dp):
        field = dp.ofproto.OXM_OF_TCP_SRC
        value = 105

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_TCP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_tcp_dst(self, dp):
        field = dp.ofproto.OXM_OF_TCP_DST
        value = 75

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_TCP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_udp_src(self, dp):
        field = dp.ofproto.OXM_OF_UDP_SRC
        value = 197

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_UDP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_udp_dst(self, dp):
        field = dp.ofproto.OXM_OF_UDP_DST
        value = 17

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_UDP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_icmpv4_type(self, dp):
        field = dp.ofproto.OXM_OF_ICMPV4_TYPE
        value = 8

        match = dp.ofproto_parser.OFPMatch()
        match.set_ip_proto(inet.IPPROTO_ICMP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_icmpv4_code(self, dp):
        field = dp.ofproto.OXM_OF_ICMPV4_CODE
        value = 2

        match = dp.ofproto_parser.OFPMatch()
        match.set_ip_proto(inet.IPPROTO_ICMP)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_arp_op(self, dp):
        field = dp.ofproto.OXM_OF_ARP_OP
        value = 2

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_arp_spa(self, dp):
        field = dp.ofproto.OXM_OF_ARP_SPA
        nw_src = '192.168.132.179'
        value = self.ipv4_to_int(nw_src)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_arp_tpa(self, dp):
        field = dp.ofproto.OXM_OF_ARP_TPA
        nw_dst = '192.168.118.85'
        value = self.ipv4_to_int(nw_dst)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_arp_sha(self, dp):
        field = dp.ofproto.OXM_OF_ARP_SHA
        arp_sha = '50:29:e7:7f:6c:7f'
        value = self.haddr_to_bin(arp_sha)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_arp_tha(self, dp):
        field = dp.ofproto.OXM_OF_ARP_THA
        arp_tha = '71:c8:72:2f:47:fd'
        value = self.haddr_to_bin(arp_tha)

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_ARP)
        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_ipv6_src(self, dp):
        field = dp.ofproto.OXM_OF_IPV6_SRC
        ipv6_src = '7527:c798:c772:4a18:117a:14ff:c1b6:e4ef'
        value = self.ipv6_to_int(ipv6_src)

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_ipv6_dst(self, dp):
        field = dp.ofproto.OXM_OF_IPV6_DST
        ipv6_dst = '8893:65b3:6b49:3bdb:3d2:9401:866c:c96'
        value = self.ipv6_to_int(ipv6_dst)

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_ipv6_flabel(self, dp):
        field = dp.ofproto.OXM_OF_IPV6_FLABEL
        value = 0x2c12

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_icmpv6_type(self, dp):
        field = dp.ofproto.OXM_OF_ICMPV6_TYPE
        value = 129

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_icmpv6_code(self, dp):
        field = dp.ofproto.OXM_OF_ICMPV6_CODE
        value = 2

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_ipv6_nd_target(self, dp):
        field = dp.ofproto.OXM_OF_IPV6_ND_TARGET
        target = "5420:db3f:921b:3e33:2791:98f:dd7f:2e19"
        value = self.ipv6_to_int(target)

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_ipv6_nd_sll(self, dp):
        field = dp.ofproto.OXM_OF_IPV6_ND_SLL
        sll = "54:db:3f:3e:27:19"
        value = self.haddr_to_bin(sll)

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_ipv6_nd_tll(self, dp):
        field = dp.ofproto.OXM_OF_IPV6_ND_TLL
        tll = "83:13:48:1e:d0:b0"
        value = self.haddr_to_bin(tll)

        self.add_set_field_action(dp, field, value)

    def test_action_set_field_mpls_label(self, dp):
        field = dp.ofproto.OXM_OF_MPLS_LABEL
        value = 0x4c

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_MPLS)

        self.add_set_field_action(dp, field, value, match)

    def test_action_set_field_mpls_tc(self, dp):
        field = dp.ofproto.OXM_OF_MPLS_TC
        value = 0b101

        match = dp.ofproto_parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_MPLS)

        self.add_set_field_action(dp, field, value, match)

    # Test of Change-TTL Actions
    def test_action_set_mpls_ttl(self, dp):
        mpls_ttl = 8
        self._verify = [dp.ofproto.OFPAT_SET_MPLS_TTL,
                        'mpls_ttl', mpls_ttl]
        actions = [dp.ofproto_parser.OFPActionSetMplsTtl(mpls_ttl), ]
        self.add_apply_actions(dp, actions)

    def test_action_dec_mpls_ttl(self, dp):
        self._verify = [dp.ofproto.OFPAT_DEC_MPLS_TTL]
        actions = [dp.ofproto_parser.OFPActionDecMplsTtl(), ]
        self.add_apply_actions(dp, actions)

    def test_action_set_nw_ttl(self, dp):
        nw_ttl = 64
        self._verify = [dp.ofproto.OFPAT_SET_NW_TTL,
                        'nw_ttl', nw_ttl]
        actions = [dp.ofproto_parser.OFPActionSetNwTtl(nw_ttl), ]
        self.add_apply_actions(dp, actions)

    def test_action_dec_nw_ttl(self, dp):
        self._verify = [dp.ofproto.OFPAT_DEC_NW_TTL]
        actions = [dp.ofproto_parser.OFPActionDecNwTtl(), ]
        self.add_apply_actions(dp, actions)

    def test_action_copy_ttl_out(self, dp):
        self._verify = [dp.ofproto.OFPAT_COPY_TTL_OUT]
        actions = [dp.ofproto_parser.OFPActionCopyTtlOut(), ]
        self.add_apply_actions(dp, actions)

    def test_action_copy_ttl_in(self, dp):
        self._verify = [dp.ofproto.OFPAT_COPY_TTL_IN]
        actions = [dp.ofproto_parser.OFPActionCopyTtlIn(), ]
        self.add_apply_actions(dp, actions)

    def is_supported(self, t):
        # Open vSwitch 1.10 does not support MPLS yet.
        unsupported = [
            'test_action_set_field_ip_proto',
            'test_action_set_field_dl_type',
            'test_action_set_field_arp',
            'test_action_set_field_ipv6',
            'test_action_set_field_icmp',
            'test_action_set_nw_ttl',
            'test_action_copy_ttl_in',
            'test_action_copy_ttl_out',
            'test_action_dec_mpls_ttl',
            'test_action_pop_mpls',
            'test_action_push_mpls',
            'test_action_set_field_mpls_label',
            'test_action_set_field_mpls_tc',
            'test_action_set_mpls_ttl'
        ]
        for u in unsupported:
            if t.find(u) != -1:
                return False

        return True
